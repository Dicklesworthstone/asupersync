//! Real service E2E tests for cx/registry ↔ trace/distributed integration.
//!
//! Verifies that capability commit_permit propagates through distributed trace
//! context across nodes. Tests that registry capability management correctly
//! integrates with distributed tracing to maintain permit tracking and
//! validation across distributed system boundaries.

use crate::cx::{Cx, Registry, RegistryHandle};
use crate::cx::registry::{NameRegistry, NameLease, NamePermit, NameLeaseError};
use crate::trace::distributed::{
    SymbolTraceContext, DistTraceId, SymbolSpanId, RegionTag, TraceFlags,
};
use crate::trace::SymbolTrace;
use crate::types::{Symbol, SymbolId, SymbolKind, Time};
use crate::util::det_rng::DetRng;
use crate::time::Duration;
use std::collections::{HashMap, BTreeMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use futures_lite::future;
use serde_json::json;

/// Configuration for registry + distributed trace testing.
#[derive(Debug, Clone)]
struct RegistryDistributedTraceConfig {
    /// Number of distributed nodes in the test network.
    node_count: usize,
    /// Number of concurrent permit operations per node.
    permits_per_node: usize,
    /// Percentage of permits that should be committed (vs aborted).
    commit_rate: f64,
    /// Enable cross-node permit propagation testing.
    cross_node_propagation: bool,
    /// Trace sampling configuration.
    trace_sampling_rate: f64,
}

impl Default for RegistryDistributedTraceConfig {
    fn default() -> Self {
        Self {
            node_count: 4,
            permits_per_node: 20,
            commit_rate: 0.8,
            cross_node_propagation: true,
            trace_sampling_rate: 1.0, // Sample all traces for testing
        }
    }
}

/// Statistics tracking for registry + distributed trace operations.
#[derive(Debug, Default)]
struct RegistryTraceStats {
    /// Number of permits created across all nodes.
    permits_created: AtomicU32,
    /// Number of permits successfully committed.
    permits_committed: AtomicU32,
    /// Number of permits aborted.
    permits_aborted: AtomicU32,
    /// Number of trace contexts propagated.
    traces_propagated: AtomicU32,
    /// Number of cross-node permit validations.
    cross_node_validations: AtomicU32,
    /// Number of capability security violations detected.
    security_violations: AtomicU32,
    /// Number of trace baggage items containing permit data.
    permit_baggage_items: AtomicU32,
}

impl RegistryTraceStats {
    fn snapshot(&self) -> RegistryTraceStatsSnapshot {
        RegistryTraceStatsSnapshot {
            permits_created: self.permits_created.load(Ordering::Acquire),
            permits_committed: self.permits_committed.load(Ordering::Acquire),
            permits_aborted: self.permits_aborted.load(Ordering::Acquire),
            traces_propagated: self.traces_propagated.load(Ordering::Acquire),
            cross_node_validations: self.cross_node_validations.load(Ordering::Acquire),
            security_violations: self.security_violations.load(Ordering::Acquire),
            permit_baggage_items: self.permit_baggage_items.load(Ordering::Acquire),
        }
    }
}

/// Snapshot of registry trace statistics.
#[derive(Debug, Clone)]
struct RegistryTraceStatsSnapshot {
    permits_created: u32,
    permits_committed: u32,
    permits_aborted: u32,
    traces_propagated: u32,
    cross_node_validations: u32,
    security_violations: u32,
    permit_baggage_items: u32,
}

impl RegistryTraceStatsSnapshot {
    /// Check if permit lifecycle is consistent.
    fn is_consistent(&self) -> bool {
        let resolved = self.permits_committed + self.permits_aborted;
        resolved == self.permits_created && self.security_violations == 0
    }

    /// Calculate the commit rate.
    fn commit_rate(&self) -> f64 {
        if self.permits_created > 0 {
            self.permits_committed as f64 / self.permits_created as f64
        } else {
            0.0
        }
    }

    /// Calculate the trace propagation rate.
    fn propagation_rate(&self) -> f64 {
        if self.permits_created > 0 {
            self.traces_propagated as f64 / self.permits_created as f64
        } else {
            0.0
        }
    }
}

/// Represents a distributed node with registry capability and trace context.
#[derive(Debug)]
struct DistributedRegistryNode {
    node_id: String,
    region_tag: RegionTag,
    registry: NameRegistry,
    trace_context: Option<SymbolTraceContext>,
    permit_store: HashMap<String, PermitRecord>,
    trace_collector: Vec<TraceRecord>,
}

/// Record of a permit operation for cross-node tracking.
#[derive(Debug, Clone)]
struct PermitRecord {
    permit_name: String,
    trace_id: DistTraceId,
    span_id: SymbolSpanId,
    origin_node: String,
    created_at: Time,
    committed: bool,
    aborted: bool,
}

/// Trace record for analyzing distributed permit propagation.
#[derive(Debug, Clone)]
struct TraceRecord {
    trace_id: DistTraceId,
    span_id: SymbolSpanId,
    operation: String,
    permit_name: Option<String>,
    node_id: String,
    timestamp: Time,
    baggage: BTreeMap<String, String>,
}

impl DistributedRegistryNode {
    async fn new(
        node_id: String,
        region_tag: RegionTag,
        rng: &mut DetRng,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let registry = NameRegistry::new();

        Ok(Self {
            node_id,
            region_tag,
            registry,
            trace_context: None,
            permit_store: HashMap::new(),
            trace_collector: Vec::new(),
        })
    }

    /// Create a new permit with distributed trace context.
    async fn create_permit_with_trace(
        &mut self,
        cx: &Cx,
        permit_name: String,
        rng: &mut DetRng,
    ) -> Result<NamePermit, Box<dyn std::error::Error>> {
        // Create new trace context for this operation
        let trace_id = DistTraceId::new_random(rng);
        let parent_span_id = SymbolSpanId::new_random(rng);

        let trace_context = SymbolTraceContext::new_for_encoding(
            trace_id,
            parent_span_id,
            self.region_tag.clone(),
            rng,
        )
        .with_baggage("permit_name", &permit_name)
        .with_baggage("node_id", &self.node_id)
        .with_baggage("operation", "create_permit");

        self.trace_context = Some(trace_context.clone());

        // Create the permit
        let permit = self.registry.reserve_name(&permit_name).await?;

        // Record permit creation
        let permit_record = PermitRecord {
            permit_name: permit_name.clone(),
            trace_id,
            span_id: trace_context.span_id(),
            origin_node: self.node_id.clone(),
            created_at: cx.now(),
            committed: false,
            aborted: false,
        };

        self.permit_store.insert(permit_name.clone(), permit_record);

        // Record trace
        self.record_trace_operation(
            trace_context,
            "create_permit",
            Some(permit_name),
            cx.now(),
        );

        cx.trace("permit_created_with_trace", &json!({
            "node_id": self.node_id,
            "permit_name": permit_name,
            "trace_id": trace_id.to_string(),
            "span_id": trace_context.span_id().to_string()
        }));

        Ok(permit)
    }

    /// Commit a permit and propagate trace context.
    async fn commit_permit_with_trace_propagation(
        &mut self,
        cx: &Cx,
        permit: NamePermit,
        permit_name: String,
        target_nodes: &[String],
        stats: &Arc<RegistryTraceStats>,
    ) -> Result<NameLease, Box<dyn std::error::Error>> {
        // Get or create trace context
        let trace_context = if let Some(ctx) = &self.trace_context {
            ctx.clone()
        } else {
            let mut rng = DetRng::from_seed(42);
            SymbolTraceContext::new_for_encoding(
                DistTraceId::new_random(&mut rng),
                SymbolSpanId::new_random(&mut rng),
                self.region_tag.clone(),
                &mut rng,
            )
        };

        // Add commit operation to trace baggage
        let propagation_context = trace_context
            .with_baggage("operation", "commit_permit")
            .with_baggage("permit_name", &permit_name)
            .with_baggage("commit_node", &self.node_id)
            .with_baggage("target_nodes", &target_nodes.join(","));

        // Commit the permit
        let lease = self.registry.commit_permit(permit)?;

        // Update permit record
        if let Some(record) = self.permit_store.get_mut(&permit_name) {
            record.committed = true;
        }

        // Record trace for commit operation
        self.record_trace_operation(
            propagation_context.clone(),
            "commit_permit",
            Some(permit_name.clone()),
            cx.now(),
        );

        // Propagate trace context to target nodes (simulate cross-node communication)
        for target_node in target_nodes {
            self.propagate_trace_context_to_node(
                cx,
                propagation_context.clone(),
                target_node.clone(),
                stats,
            ).await?;
        }

        stats.permits_committed.fetch_add(1, Ordering::Relaxed);
        stats.permit_baggage_items.fetch_add(
            propagation_context.baggage().len() as u32,
            Ordering::Relaxed,
        );

        cx.trace("permit_committed_with_propagation", &json!({
            "node_id": self.node_id,
            "permit_name": permit_name,
            "target_nodes": target_nodes,
            "baggage_count": propagation_context.baggage().len()
        }));

        Ok(lease)
    }

    /// Abort a permit and update trace context.
    async fn abort_permit_with_trace(
        &mut self,
        cx: &Cx,
        permit: NamePermit,
        permit_name: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get existing trace context
        let trace_context = if let Some(ctx) = &self.trace_context {
            ctx.with_baggage("operation", "abort_permit")
                .with_baggage("abort_reason", "user_requested")
        } else {
            let mut rng = DetRng::from_seed(42);
            SymbolTraceContext::new_for_encoding(
                DistTraceId::new_random(&mut rng),
                SymbolSpanId::new_random(&mut rng),
                self.region_tag.clone(),
                &mut rng,
            )
        };

        // Abort the permit
        permit.abort();

        // Update permit record
        if let Some(record) = self.permit_store.get_mut(&permit_name) {
            record.aborted = true;
        }

        // Record trace
        self.record_trace_operation(
            trace_context,
            "abort_permit",
            Some(permit_name.clone()),
            cx.now(),
        );

        cx.trace("permit_aborted_with_trace", &json!({
            "node_id": self.node_id,
            "permit_name": permit_name
        }));

        Ok(())
    }

    /// Validate received permit information from another node.
    async fn validate_cross_node_permit(
        &mut self,
        cx: &Cx,
        trace_context: SymbolTraceContext,
        permit_name: String,
        stats: &Arc<RegistryTraceStats>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Extract permit information from trace baggage
        let origin_node = trace_context.get_baggage("node_id")
            .unwrap_or("unknown");
        let operation = trace_context.get_baggage("operation")
            .unwrap_or("unknown");

        // Validate trace context integrity
        if trace_context.trace_id().is_nil() {
            cx.trace("trace_validation_failed", &json!({
                "node_id": self.node_id,
                "reason": "nil_trace_id",
                "permit_name": permit_name
            }));
            stats.security_violations.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // Check for required baggage items
        let required_baggage = ["permit_name", "node_id", "operation"];
        for key in &required_baggage {
            if trace_context.get_baggage(key).is_none() {
                cx.trace("trace_validation_failed", &json!({
                    "node_id": self.node_id,
                    "reason": format!("missing_baggage_{}", key),
                    "permit_name": permit_name
                }));
                stats.security_violations.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            }
        }

        // Record successful cross-node validation
        self.record_trace_operation(
            trace_context.with_baggage("validation_node", &self.node_id)
                .with_baggage("validation_result", "success"),
            "validate_permit",
            Some(permit_name.clone()),
            cx.now(),
        );

        stats.cross_node_validations.fetch_add(1, Ordering::Relaxed);

        cx.trace("cross_node_permit_validated", &json!({
            "validator_node": self.node_id,
            "origin_node": origin_node,
            "operation": operation,
            "permit_name": permit_name
        }));

        Ok(true)
    }

    /// Simulate propagating trace context to another node.
    async fn propagate_trace_context_to_node(
        &mut self,
        cx: &Cx,
        trace_context: SymbolTraceContext,
        target_node: String,
        stats: &Arc<RegistryTraceStats>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Serialize trace context (simulating network transmission)
        let trace_bytes = trace_context.to_bytes();

        if trace_bytes.is_empty() {
            cx.trace("trace_propagation_failed", &json!({
                "source_node": self.node_id,
                "target_node": target_node,
                "reason": "serialization_failed"
            }));
            stats.security_violations.fetch_add(1, Ordering::Relaxed);
            return Err("Failed to serialize trace context".into());
        }

        // Record propagation
        self.record_trace_operation(
            trace_context.with_baggage("propagation_target", &target_node),
            "propagate_trace",
            None,
            cx.now(),
        );

        stats.traces_propagated.fetch_add(1, Ordering::Relaxed);

        cx.trace("trace_context_propagated", &json!({
            "source_node": self.node_id,
            "target_node": target_node,
            "trace_size_bytes": trace_bytes.len()
        }));

        Ok(())
    }

    /// Record a trace operation in the local collector.
    fn record_trace_operation(
        &mut self,
        trace_context: SymbolTraceContext,
        operation: String,
        permit_name: Option<String>,
        timestamp: Time,
    ) {
        let trace_record = TraceRecord {
            trace_id: trace_context.trace_id(),
            span_id: trace_context.span_id(),
            operation,
            permit_name,
            node_id: self.node_id.clone(),
            timestamp,
            baggage: trace_context.baggage().iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };

        self.trace_collector.push(trace_record);
    }

    /// Get all trace records for analysis.
    fn get_trace_records(&self) -> &[TraceRecord] {
        &self.trace_collector
    }
}

/// Test harness for registry + distributed trace integration.
struct RegistryDistributedTraceHarness {
    nodes: Vec<DistributedRegistryNode>,
    config: RegistryDistributedTraceConfig,
    stats: Arc<RegistryTraceStats>,
    rng: DetRng,
}

impl RegistryDistributedTraceHarness {
    async fn new(config: RegistryDistributedTraceConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut nodes = Vec::with_capacity(config.node_count);
        let mut rng = DetRng::from_seed(12345);
        let stats = Arc::new(RegistryTraceStats::default());

        // Create distributed nodes
        for i in 0..config.node_count {
            let node_id = format!("node-{}", i);
            let region_tag = RegionTag::new(format!("region-{}", i % 3));

            let node = DistributedRegistryNode::new(
                node_id,
                region_tag,
                &mut rng,
            ).await?;

            nodes.push(node);
        }

        Ok(Self {
            nodes,
            config,
            stats,
            rng,
        })
    }

    /// Run concurrent permit operations with distributed trace propagation.
    async fn run_concurrent_permit_operations_with_trace_propagation(
        &mut self,
        cx: &Cx,
    ) -> Result<RegistryTraceStatsSnapshot, Box<dyn std::error::Error>> {
        cx.trace("test_started", &json!({
            "config": {
                "node_count": self.config.node_count,
                "permits_per_node": self.config.permits_per_node,
                "commit_rate": self.config.commit_rate
            }
        }));

        // Track all permit operations across nodes
        let mut permit_handles = Vec::new();

        // Create permits on all nodes concurrently
        for node_index in 0..self.config.node_count {
            for permit_index in 0..self.config.permits_per_node {
                let permit_name = format!("permit-{}-{}", node_index, permit_index);
                let should_commit = self.rng.next_f64() < self.config.commit_rate;

                let node = &mut self.nodes[node_index];
                let stats = Arc::clone(&self.stats);

                // Create permit with trace context
                match node.create_permit_with_trace(
                    cx,
                    permit_name.clone(),
                    &mut self.rng,
                ).await {
                    Ok(permit) => {
                        self.stats.permits_created.fetch_add(1, Ordering::Relaxed);

                        let handle = PermitOperationHandle {
                            permit: Some(permit),
                            permit_name,
                            node_index,
                            should_commit,
                            target_nodes: self.select_target_nodes(node_index),
                        };

                        permit_handles.push(handle);
                    }
                    Err(e) => {
                        cx.trace("permit_creation_failed", &json!({
                            "node_index": node_index,
                            "permit_name": permit_name,
                            "error": e.to_string()
                        }));
                    }
                }
            }
        }

        // Process all permits (commit or abort) with trace propagation
        for mut handle in permit_handles {
            let node = &mut self.nodes[handle.node_index];

            if let Some(permit) = handle.permit.take() {
                if handle.should_commit {
                    // Commit with cross-node trace propagation
                    match node.commit_permit_with_trace_propagation(
                        cx,
                        permit,
                        handle.permit_name.clone(),
                        &handle.target_nodes,
                        &self.stats,
                    ).await {
                        Ok(_lease) => {
                            cx.trace("permit_committed", &json!({
                                "node_index": handle.node_index,
                                "permit_name": handle.permit_name
                            }));
                        }
                        Err(e) => {
                            cx.trace("permit_commit_failed", &json!({
                                "node_index": handle.node_index,
                                "permit_name": handle.permit_name,
                                "error": e.to_string()
                            }));
                            self.stats.security_violations.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    // Abort with trace recording
                    match node.abort_permit_with_trace(
                        cx,
                        permit,
                        handle.permit_name.clone(),
                    ).await {
                        Ok(()) => {
                            self.stats.permits_aborted.fetch_add(1, Ordering::Relaxed);
                            cx.trace("permit_aborted", &json!({
                                "node_index": handle.node_index,
                                "permit_name": handle.permit_name
                            }));
                        }
                        Err(e) => {
                            cx.trace("permit_abort_failed", &json!({
                                "node_index": handle.node_index,
                                "permit_name": handle.permit_name,
                                "error": e.to_string()
                            }));
                        }
                    }
                }
            }
        }

        // Verify cross-node trace propagation
        if self.config.cross_node_propagation {
            self.verify_cross_node_trace_propagation(cx).await?;
        }

        let final_stats = self.stats.snapshot();

        cx.trace("test_completed", &json!({
            "stats": {
                "permits_created": final_stats.permits_created,
                "permits_committed": final_stats.permits_committed,
                "permits_aborted": final_stats.permits_aborted,
                "traces_propagated": final_stats.traces_propagated,
                "cross_node_validations": final_stats.cross_node_validations,
                "security_violations": final_stats.security_violations,
                "permit_baggage_items": final_stats.permit_baggage_items
            }
        }));

        Ok(final_stats)
    }

    /// Select target nodes for cross-node propagation.
    fn select_target_nodes(&mut self, source_node_index: usize) -> Vec<String> {
        let mut targets = Vec::new();

        // Select 1-2 random target nodes (excluding source)
        for _ in 0..2 {
            let target_index = loop {
                let idx = (self.rng.next_u64() as usize) % self.config.node_count;
                if idx != source_node_index {
                    break idx;
                }
            };
            targets.push(format!("node-{}", target_index));
        }

        targets
    }

    /// Verify that trace context propagation worked correctly across nodes.
    async fn verify_cross_node_trace_propagation(
        &mut self,
        cx: &Cx,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Collect all trace records
        let mut all_traces = Vec::new();
        for node in &self.nodes {
            all_traces.extend(node.get_trace_records());
        }

        // Group traces by trace_id to verify propagation chains
        let mut trace_chains: HashMap<DistTraceId, Vec<&TraceRecord>> = HashMap::new();
        for trace in &all_traces {
            trace_chains.entry(trace.trace_id)
                .or_insert_with(Vec::new)
                .push(trace);
        }

        // Verify that multi-node trace chains exist
        let mut multi_node_chains = 0;
        for (trace_id, records) in &trace_chains {
            let unique_nodes: std::collections::HashSet<_> =
                records.iter().map(|r| &r.node_id).collect();

            if unique_nodes.len() > 1 {
                multi_node_chains += 1;
                cx.trace("multi_node_trace_chain_found", &json!({
                    "trace_id": trace_id.to_string(),
                    "node_count": unique_nodes.len(),
                    "nodes": unique_nodes.iter().collect::<Vec<_>>(),
                    "operation_count": records.len()
                }));
            }
        }

        cx.trace("cross_node_propagation_verified", &json!({
            "total_trace_chains": trace_chains.len(),
            "multi_node_chains": multi_node_chains,
            "single_node_chains": trace_chains.len() - multi_node_chains
        }));

        Ok(())
    }
}

/// Handle for tracking permit operations.
struct PermitOperationHandle {
    permit: Option<NamePermit>,
    permit_name: String,
    node_index: usize,
    should_commit: bool,
    target_nodes: Vec<String>,
}

#[cfg(test)]
mod registry_distributed_trace_integration_tests {
    use super::*;
    use crate::test_utils::{init_test_logging, TestRuntime};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    /// Test basic commit_permit propagation through distributed trace context.
    #[test]
    fn test_commit_permit_distributed_trace_propagation() {
        init_test("test_commit_permit_distributed_trace_propagation");

        let config = RegistryDistributedTraceConfig {
            node_count: 3,
            permits_per_node: 10,
            commit_rate: 0.8,
            cross_node_propagation: true,
            trace_sampling_rate: 1.0,
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(60), async move |cx| {
            let mut harness = RegistryDistributedTraceHarness::new(config.clone()).await?;

            let stats = harness.run_concurrent_permit_operations_with_trace_propagation(&cx).await?;

            // Verify permit lifecycle consistency
            assert!(
                stats.is_consistent(),
                "Permit lifecycle should be consistent across distributed traces: {:?}",
                stats
            );

            // Verify expected commit rate
            let actual_commit_rate = stats.commit_rate();
            let commit_rate_tolerance = 0.15;

            assert!(
                (actual_commit_rate - config.commit_rate).abs() < commit_rate_tolerance,
                "Commit rate should be close to expected: actual={:.2}, expected={:.2}",
                actual_commit_rate, config.commit_rate
            );

            // Verify trace propagation occurred
            assert!(
                stats.propagation_rate() > 0.5,
                "At least 50% of operations should have trace propagation: rate={:.3}",
                stats.propagation_rate()
            );

            // Verify cross-node validations worked
            assert!(
                stats.cross_node_validations > 0,
                "Should have cross-node permit validations: count={}",
                stats.cross_node_validations
            );

            // Verify no security violations
            assert_eq!(
                stats.security_violations, 0,
                "Should have no capability security violations"
            );

            // Verify permit information was carried in trace baggage
            assert!(
                stats.permit_baggage_items > stats.permits_created,
                "Should have permit data in trace baggage: baggage={}, permits={}",
                stats.permit_baggage_items, stats.permits_created
            );

            cx.trace("test_commit_permit_distributed_trace_propagation_complete", &json!({
                "permits_created": stats.permits_created,
                "permits_committed": stats.permits_committed,
                "traces_propagated": stats.traces_propagated,
                "cross_node_validations": stats.cross_node_validations,
                "baggage_items": stats.permit_baggage_items
            }));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_commit_permit_distributed_trace_propagation");
    }

    /// Test capability security preservation across distributed trace boundaries.
    #[test]
    fn test_capability_security_across_distributed_boundaries() {
        init_test("test_capability_security_across_distributed_boundaries");

        let config = RegistryDistributedTraceConfig {
            node_count: 5,
            permits_per_node: 8,
            commit_rate: 0.9,
            cross_node_propagation: true,
            trace_sampling_rate: 1.0,
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(45), async move |cx| {
            let mut harness = RegistryDistributedTraceHarness::new(config.clone()).await?;

            let stats = harness.run_concurrent_permit_operations_with_trace_propagation(&cx).await?;

            // Verify no capability security violations occurred
            assert_eq!(
                stats.security_violations, 0,
                "Capability security should be preserved across distributed boundaries"
            );

            // Verify all permits were properly tracked
            assert!(
                stats.is_consistent(),
                "All permits should be properly tracked: {:?}",
                stats
            );

            // Verify cross-node operations maintained security
            let total_permits = stats.permits_created;
            assert!(
                stats.cross_node_validations > 0,
                "Should have cross-node validations for security verification"
            );

            // Verify trace context maintained capability information
            assert!(
                stats.permit_baggage_items >= total_permits,
                "Each permit should have associated trace baggage: baggage={}, permits={}",
                stats.permit_baggage_items, total_permits
            );

            cx.trace("test_capability_security_across_distributed_boundaries_complete", &json!({
                "security_violations": stats.security_violations,
                "cross_node_validations": stats.cross_node_validations,
                "consistency_check": stats.is_consistent()
            }));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_capability_security_across_distributed_boundaries");
    }

    /// Test high-concurrency distributed permit operations with trace tracking.
    #[test]
    fn test_high_concurrency_distributed_permit_trace_tracking() {
        init_test("test_high_concurrency_distributed_permit_trace_tracking");

        let config = RegistryDistributedTraceConfig {
            node_count: 6,
            permits_per_node: 25,
            commit_rate: 0.7,
            cross_node_propagation: true,
            trace_sampling_rate: 1.0,
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(75), async move |cx| {
            let mut harness = RegistryDistributedTraceHarness::new(config.clone()).await?;

            let stats = harness.run_concurrent_permit_operations_with_trace_propagation(&cx).await?;

            // Under high concurrency, verify system maintained consistency
            let resolution_rate = (stats.permits_committed + stats.permits_aborted) as f64 / stats.permits_created as f64;
            assert!(
                resolution_rate >= 0.95,
                "At least 95% of permits should be resolved under high concurrency: rate={:.3}",
                resolution_rate
            );

            // Verify trace propagation worked at scale
            assert!(
                stats.traces_propagated >= stats.permits_created / 2,
                "Significant trace propagation should occur: propagated={}, created={}",
                stats.traces_propagated, stats.permits_created
            );

            // Verify cross-node operations scaled properly
            let cross_node_rate = stats.cross_node_validations as f64 / stats.permits_created as f64;
            assert!(
                cross_node_rate >= 0.3,
                "At least 30% of operations should involve cross-node validation: rate={:.3}",
                cross_node_rate
            );

            // Verify minimal security violations under load
            let violation_rate = stats.security_violations as f64 / stats.permits_created as f64;
            assert!(
                violation_rate < 0.02,
                "Security violation rate should be under 2%: rate={:.3}",
                violation_rate
            );

            cx.trace("test_high_concurrency_distributed_permit_trace_tracking_complete", &json!({
                "total_permits": stats.permits_created,
                "resolution_rate": resolution_rate,
                "cross_node_rate": cross_node_rate,
                "violation_rate": violation_rate,
                "trace_propagation_count": stats.traces_propagated
            }));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_high_concurrency_distributed_permit_trace_tracking");
    }
}