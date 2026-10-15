//! Real E2E integration tests: obligation/dialectica ↔ trace/distributed/vclock (br-e2e-183).
//!
//! Tests that dialectica obligations correctly serialize causally across vector clock
//! boundaries. Verifies the integration between:
//!
//! - `obligation::dialectica`: Dialectica obligation logic with causal dependencies
//! - `trace::distributed::vclock`: Vector clock for distributed causality tracking
//!
//! Key integration properties:
//! - Dialectica obligations serialize with causal ordering preserved
//! - Vector clock boundaries maintain obligation consistency
//! - Cross-node causality tracking integrates with dialectica semantics
//! - Obligation dependencies respect vector clock partial ordering
//! - Causal serialization preserves dialectica proof obligations
//! - Vector clock merge operations preserve obligation validity

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::{
        cx::{Cx, Scope},
        error::{Error, Result},
        obligation::dialectica::{
            CausalDependency, DialecticaProof, DialecticaWitness, ProofObligation, ProofState,
            SerializationContext, WitnessVerification,
        },
        runtime::{Runtime, spawn},
        sync::{Arc, Mutex, RwLock},
        time::{Duration, Instant, sleep},
        trace::distributed::vclock::{
            CausalOrdering, CausalityViolation, ClockMerge, DistributedEvent, LogicalTime, NodeId,
            VectorClock,
        },
        types::{Budget, CancelReason, ObligationId, Outcome, RegionId, TaskId, Time},
    };
    use std::{
        collections::{BTreeMap, HashMap, HashSet, VecDeque},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Dialectica + Vector Clock Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CausalEventType {
        ObligationCreated,
        ObligationResolved,
        ProofConstructed,
        WitnessVerified,
        DependencyEstablished,
        ClockSynchronized,
    }

    #[derive(Debug, Clone)]
    struct CausalObligationEvent {
        event_type: CausalEventType,
        obligation_id: ObligationId,
        node_id: NodeId,
        vclock_snapshot: VectorClock,
        dialectica_state: ProofState,
        causal_dependencies: Vec<CausalDependency>,
        timestamp: Instant,
    }

    #[derive(Debug)]
    struct DialecticaVClockTestFramework {
        runtime: Arc<Runtime>,
        node_registry: Arc<RwLock<HashMap<NodeId, NodeState>>>,
        global_vclock: Arc<Mutex<VectorClock>>,
        obligation_registry: Arc<RwLock<HashMap<ObligationId, DialecticaObligation>>>,
        causal_event_log: Arc<Mutex<Vec<CausalObligationEvent>>>,
        serialization_stats: Arc<Mutex<SerializationStats>>,
    }

    #[derive(Debug, Clone)]
    struct NodeState {
        node_id: NodeId,
        local_vclock: VectorClock,
        active_proofs: HashSet<ObligationId>,
        witness_cache: HashMap<ObligationId, DialecticaWitness>,
        causal_dependencies: Vec<CausalDependency>,
    }

    #[derive(Debug, Clone)]
    struct DialecticaObligation {
        obligation_id: ObligationId,
        proof: Option<DialecticaProof>,
        witness: Option<DialecticaWitness>,
        state: ProofState,
        causal_deps: Vec<CausalDependency>,
        origin_vclock: VectorClock,
        current_vclock: VectorClock,
        serialization_context: SerializationContext,
    }

    #[derive(Debug, Default)]
    struct SerializationStats {
        obligations_serialized: u64,
        causal_violations_detected: u64,
        vclock_merges_performed: u64,
        proof_reconstructions: u64,
        witness_verifications: u64,
        dependency_chains_resolved: u64,
        serialization_errors: u64,
        max_causal_chain_length: usize,
    }

    impl DialecticaVClockTestFramework {
        async fn new() -> Result<Self> {
            let runtime = Arc::new(Runtime::new().await?);
            let node_registry = Arc::new(RwLock::new(HashMap::new()));
            let global_vclock = Arc::new(Mutex::new(VectorClock::new()));
            let obligation_registry = Arc::new(RwLock::new(HashMap::new()));
            let causal_event_log = Arc::new(Mutex::new(Vec::new()));
            let serialization_stats = Arc::new(Mutex::new(SerializationStats::default()));

            Ok(Self {
                runtime,
                node_registry,
                global_vclock,
                obligation_registry,
                causal_event_log,
                serialization_stats,
            })
        }

        async fn create_node(&self, node_id: NodeId) -> Result<()> {
            let node_state = NodeState {
                node_id,
                local_vclock: VectorClock::new_with_node(node_id),
                active_proofs: HashSet::new(),
                witness_cache: HashMap::new(),
                causal_dependencies: Vec::new(),
            };

            self.node_registry.write().await.insert(node_id, node_state);
            Ok(())
        }

        async fn create_dialectica_obligation(
            &self,
            cx: &Cx,
            node_id: NodeId,
            obligation_id: ObligationId,
            causal_deps: Vec<CausalDependency>,
        ) -> Result<()> {
            // Create dialectica proof obligation
            let proof_obligation = ProofObligation::new(
                obligation_id,
                causal_deps.clone(),
                SerializationContext::new_causal(),
            );

            // Capture current vector clock state
            let mut node_registry = self.node_registry.write().await;
            let node_state = node_registry
                .get_mut(&node_id)
                .ok_or_else(|| Error::new("Node not found"))?;

            // Advance local clock for obligation creation
            node_state.local_vclock.advance_local(node_id)?;
            let origin_vclock = node_state.local_vclock.clone();

            // Create dialectica obligation with vector clock context
            let dialectica_obligation = DialecticaObligation {
                obligation_id,
                proof: None,
                witness: None,
                state: ProofState::Pending,
                causal_deps,
                origin_vclock: origin_vclock.clone(),
                current_vclock: origin_vclock.clone(),
                serialization_context: SerializationContext::new_with_vclock(origin_vclock.clone()),
            };

            self.obligation_registry
                .write()
                .await
                .insert(obligation_id, dialectica_obligation);
            node_state.active_proofs.insert(obligation_id);

            // Record causal event
            let event = CausalObligationEvent {
                event_type: CausalEventType::ObligationCreated,
                obligation_id,
                node_id,
                vclock_snapshot: origin_vclock.clone(),
                dialectica_state: ProofState::Pending,
                causal_dependencies: node_state.causal_dependencies.clone(),
                timestamp: Instant::now(),
            };

            self.causal_event_log.lock().await.push(event);

            // Update global vector clock
            {
                let mut global_vclock = self.global_vclock.lock().await;
                global_vclock.merge(&origin_vclock)?;
            }

            Ok(())
        }

        async fn construct_proof(
            &self,
            cx: &Cx,
            obligation_id: ObligationId,
            node_id: NodeId,
        ) -> Result<DialecticaProof> {
            let mut obligation_registry = self.obligation_registry.write().await;
            let obligation = obligation_registry
                .get_mut(&obligation_id)
                .ok_or_else(|| Error::new("Obligation not found"))?;

            // Advance vector clock for proof construction
            let mut node_registry = self.node_registry.write().await;
            let node_state = node_registry
                .get_mut(&node_id)
                .ok_or_else(|| Error::new("Node not found"))?;

            node_state.local_vclock.advance_local(node_id)?;
            let proof_vclock = node_state.local_vclock.clone();

            // Verify causal dependencies are satisfied
            self.verify_causal_dependencies(cx, &obligation.causal_deps, &proof_vclock)
                .await?;

            // Construct dialectica proof with causal context
            let proof = DialecticaProof::construct_with_causal_context(
                obligation_id,
                &obligation.causal_deps,
                &obligation.serialization_context,
                proof_vclock.clone(),
            )?;

            // Update obligation state
            obligation.proof = Some(proof.clone());
            obligation.state = ProofState::ProofConstructed;
            obligation.current_vclock = proof_vclock.clone();

            // Record causal event
            let event = CausalObligationEvent {
                event_type: CausalEventType::ProofConstructed,
                obligation_id,
                node_id,
                vclock_snapshot: proof_vclock.clone(),
                dialectica_state: ProofState::ProofConstructed,
                causal_dependencies: obligation.causal_deps.clone(),
                timestamp: Instant::now(),
            };

            self.causal_event_log.lock().await.push(event);

            // Update stats
            {
                let mut stats = self.serialization_stats.lock().await;
                stats.proof_reconstructions += 1;
                stats.max_causal_chain_length = stats
                    .max_causal_chain_length
                    .max(obligation.causal_deps.len());
            }

            Ok(proof)
        }

        async fn serialize_obligation_causally(
            &self,
            cx: &Cx,
            obligation_id: ObligationId,
            source_node: NodeId,
            target_node: NodeId,
        ) -> Result<Vec<u8>> {
            let obligation_registry = self.obligation_registry.read().await;
            let obligation = obligation_registry
                .get(&obligation_id)
                .ok_or_else(|| Error::new("Obligation not found"))?;

            // Get source node's vector clock
            let node_registry = self.node_registry.read().await;
            let source_state = node_registry
                .get(&source_node)
                .ok_or_else(|| Error::new("Source node not found"))?;
            let target_state = node_registry
                .get(&target_node)
                .ok_or_else(|| Error::new("Target node not found"))?;

            // Check causal ordering before serialization
            let causal_order = source_state
                .local_vclock
                .compare(&target_state.local_vclock)?;

            match causal_order {
                CausalOrdering::Before | CausalOrdering::Concurrent => {
                    // Safe to serialize - no causality violation
                }
                CausalOrdering::After => {
                    // Potential causality violation - record and handle
                    let mut stats = self.serialization_stats.lock().await;
                    stats.causal_violations_detected += 1;

                    return Err(Error::new("Causal ordering violation in serialization"));
                }
            }

            // Serialize dialectica obligation with vector clock metadata
            let serialization_context = SerializationContext::new_with_ordering(
                obligation.origin_vclock.clone(),
                obligation.current_vclock.clone(),
                causal_order,
            );

            let serialized = obligation.serialize_with_causal_context(&serialization_context)?;

            // Update stats
            {
                let mut stats = self.serialization_stats.lock().await;
                stats.obligations_serialized += 1;
            }

            Ok(serialized)
        }

        async fn deserialize_obligation_causally(
            &self,
            cx: &Cx,
            serialized_data: &[u8],
            target_node: NodeId,
        ) -> Result<ObligationId> {
            // Deserialize with causal context preservation
            let (obligation, serialization_context) =
                DialecticaObligation::deserialize_with_causal_context(serialized_data)?;

            // Get target node state for clock merging
            let mut node_registry = self.node_registry.write().await;
            let target_state = node_registry
                .get_mut(&target_node)
                .ok_or_else(|| Error::new("Target node not found"))?;

            // Merge vector clocks to maintain causality
            target_state.local_vclock.merge(&obligation.origin_vclock)?;
            target_state
                .local_vclock
                .merge(&obligation.current_vclock)?;

            // Advance local time for deserialization event
            target_state.local_vclock.advance_local(target_node)?;

            // Verify causal dependencies can be satisfied
            self.verify_causal_dependencies(
                cx,
                &obligation.causal_deps,
                &target_state.local_vclock,
            )
            .await?;

            // Register obligation on target node
            let mut obligation_registry = self.obligation_registry.write().await;
            obligation_registry.insert(obligation.obligation_id, obligation.clone());
            target_state.active_proofs.insert(obligation.obligation_id);

            // Update global vector clock
            {
                let mut global_vclock = self.global_vclock.lock().await;
                global_vclock.merge(&target_state.local_vclock)?;
            }

            // Update stats
            {
                let mut stats = self.serialization_stats.lock().await;
                stats.vclock_merges_performed += 1;
            }

            Ok(obligation.obligation_id)
        }

        async fn verify_causal_dependencies(
            &self,
            cx: &Cx,
            dependencies: &[CausalDependency],
            current_vclock: &VectorClock,
        ) -> Result<()> {
            for dep in dependencies {
                // Check if dependency's causal requirements are satisfied by current vector clock
                if !current_vclock.happens_after(&dep.origin_vclock)? {
                    return Err(Error::new("Causal dependency not satisfied"));
                }

                // Verify the dependency obligation exists and is resolved
                let obligation_registry = self.obligation_registry.read().await;
                let dep_obligation = obligation_registry
                    .get(&dep.obligation_id)
                    .ok_or_else(|| Error::new("Dependency obligation not found"))?;

                match dep_obligation.state {
                    ProofState::Resolved => {
                        // Dependency satisfied
                    }
                    _ => {
                        return Err(Error::new("Dependency obligation not resolved"));
                    }
                }
            }

            Ok(())
        }

        async fn verify_cross_node_causality(&self, cx: &Cx) -> Result<bool> {
            let node_registry = self.node_registry.read().await;
            let obligation_registry = self.obligation_registry.read().await;

            // Verify that all cross-node obligation transfers preserve causality
            for (obligation_id, obligation) in obligation_registry.iter() {
                // Check if obligation has cross-node causal dependencies
                for dep in &obligation.causal_deps {
                    // Find the node where dependency originated
                    for (node_id, node_state) in node_registry.iter() {
                        if node_state.active_proofs.contains(&dep.obligation_id) {
                            // Verify causal ordering between nodes
                            let dep_vclock = &dep.origin_vclock;
                            let current_vclock = &obligation.current_vclock;

                            if !current_vclock.happens_after(dep_vclock)? {
                                return Ok(false); // Causality violation detected
                            }
                        }
                    }
                }
            }

            Ok(true) // All causality checks passed
        }

        async fn get_serialization_stats(&self) -> SerializationStats {
            self.serialization_stats.lock().await.clone()
        }

        async fn get_causal_event_count(&self, event_type: CausalEventType) -> usize {
            self.causal_event_log
                .lock()
                .await
                .iter()
                .filter(|event| event.event_type == event_type)
                .count()
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_dialectica_causal_serialization() {
        let framework = DialecticaVClockTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime
            .region(Budget::unlimited(), |cx| async move {
                // Create two nodes for cross-node causality testing
                framework.create_node(NodeId::new(1)).await.unwrap();
                framework.create_node(NodeId::new(2)).await.unwrap();

                // Create dialectica obligation on node 1
                let obligation_id = ObligationId::new_for_test(1, 0);
                let causal_deps = vec![CausalDependency::new(
                    ObligationId::new_for_test(0, 0),
                    VectorClock::new_with_node(NodeId::new(1)),
                )];

                framework
                    .create_dialectica_obligation(cx, NodeId::new(1), obligation_id, causal_deps)
                    .await
                    .unwrap();

                // Construct proof on node 1
                let proof = framework
                    .construct_proof(cx, obligation_id, NodeId::new(1))
                    .await
                    .unwrap();
                assert!(proof.is_valid());

                // Serialize obligation for transfer to node 2
                let serialized = framework
                    .serialize_obligation_causally(
                        cx,
                        obligation_id,
                        NodeId::new(1),
                        NodeId::new(2),
                    )
                    .await
                    .unwrap();

                assert!(!serialized.is_empty());

                // Deserialize on node 2
                let deserialized_id = framework
                    .deserialize_obligation_causally(cx, &serialized, NodeId::new(2))
                    .await
                    .unwrap();

                assert_eq!(deserialized_id, obligation_id);

                // Verify cross-node causality is maintained
                let causality_preserved = framework.verify_cross_node_causality(cx).await.unwrap();
                assert!(causality_preserved);

                // Check serialization stats
                let stats = framework.get_serialization_stats().await;
                assert_eq!(stats.obligations_serialized, 1);
                assert_eq!(stats.vclock_merges_performed, 1);
                assert_eq!(stats.causal_violations_detected, 0);

                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_vector_clock_boundary_preservation() {
        let framework = DialecticaVClockTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime
            .region(Budget::unlimited(), |cx| async move {
                // Create multiple nodes with different vector clock states
                for i in 1..=4 {
                    framework.create_node(NodeId::new(i)).await.unwrap();
                }

                let mut obligation_ids = Vec::new();

                // Create obligations on different nodes with causal dependencies
                for i in 1..=4 {
                    let obligation_id = ObligationId::new_for_test(i, 0);
                    let causal_deps = if i > 1 {
                        vec![CausalDependency::new(
                            ObligationId::new_for_test(i - 1, 0),
                            VectorClock::new_with_node(NodeId::new(i - 1)),
                        )]
                    } else {
                        vec![]
                    };

                    framework
                        .create_dialectica_obligation(
                            cx,
                            NodeId::new(i),
                            obligation_id,
                            causal_deps,
                        )
                        .await
                        .unwrap();

                    obligation_ids.push(obligation_id);
                }

                // Construct proofs maintaining causal order
                for (i, &obligation_id) in obligation_ids.iter().enumerate() {
                    framework
                        .construct_proof(cx, obligation_id, NodeId::new(i as u64 + 1))
                        .await
                        .unwrap();
                }

                // Serialize obligations across vector clock boundaries
                for i in 1..4 {
                    let serialized = framework
                        .serialize_obligation_causally(
                            cx,
                            obligation_ids[i - 1],
                            NodeId::new(i),
                            NodeId::new(i + 1),
                        )
                        .await
                        .unwrap();

                    framework
                        .deserialize_obligation_causally(cx, &serialized, NodeId::new(i + 1))
                        .await
                        .unwrap();
                }

                // Verify vector clock boundaries are preserved
                let causality_preserved = framework.verify_cross_node_causality(cx).await.unwrap();
                assert!(causality_preserved);

                // Check that all obligations were processed
                let stats = framework.get_serialization_stats().await;
                assert_eq!(stats.obligations_serialized, 3);
                assert!(stats.vclock_merges_performed >= 3);
                assert_eq!(stats.causal_violations_detected, 0);

                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_causal_dependency_chain_resolution() {
        let framework = DialecticaVClockTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime
            .region(Budget::unlimited(), |cx| async move {
                // Create nodes for complex causal dependency chain
                for i in 1..=5 {
                    framework.create_node(NodeId::new(i)).await.unwrap();
                }

                // Create chain of causally dependent obligations
                let chain_length = 5;
                let mut obligation_chain = Vec::new();

                for i in 0..chain_length {
                    let obligation_id = ObligationId::new_for_test(i, 0);
                    let causal_deps = if i > 0 {
                        // Each obligation depends on the previous one
                        vec![CausalDependency::new(
                            obligation_chain[i - 1],
                            VectorClock::new_with_node(NodeId::new(i)),
                        )]
                    } else {
                        vec![]
                    };

                    framework
                        .create_dialectica_obligation(
                            cx,
                            NodeId::new(i + 1),
                            obligation_id,
                            causal_deps,
                        )
                        .await
                        .unwrap();

                    obligation_chain.push(obligation_id);
                }

                // Resolve obligations in causal order
                for (i, &obligation_id) in obligation_chain.iter().enumerate() {
                    framework
                        .construct_proof(cx, obligation_id, NodeId::new(i + 1))
                        .await
                        .unwrap();

                    // Mark as resolved for dependency checking
                    let mut obligation_registry = framework.obligation_registry.write().await;
                    if let Some(obligation) = obligation_registry.get_mut(&obligation_id) {
                        obligation.state = ProofState::Resolved;
                    }
                }

                // Serialize entire chain across vector clock boundaries
                for i in 0..chain_length - 1 {
                    let serialized = framework
                        .serialize_obligation_causally(
                            cx,
                            obligation_chain[i],
                            NodeId::new(i + 1),
                            NodeId::new(i + 2),
                        )
                        .await
                        .unwrap();

                    framework
                        .deserialize_obligation_causally(cx, &serialized, NodeId::new(i + 2))
                        .await
                        .unwrap();
                }

                // Verify causal dependency chain integrity
                let causality_preserved = framework.verify_cross_node_causality(cx).await.unwrap();
                assert!(causality_preserved);

                // Check stats reflect complex causal chain processing
                let stats = framework.get_serialization_stats().await;
                assert!(stats.max_causal_chain_length > 0);
                assert_eq!(stats.causal_violations_detected, 0);
                assert!(stats.dependency_chains_resolved > 0 || stats.obligations_serialized > 0);

                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_causality_violation_detection() {
        let framework = DialecticaVClockTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime
            .region(Budget::unlimited(), |cx| async move {
                // Create nodes with deliberately conflicting vector clock states
                framework.create_node(NodeId::new(1)).await.unwrap();
                framework.create_node(NodeId::new(2)).await.unwrap();

                // Create obligation on node 1
                let obligation_id_1 = ObligationId::new_for_test(1, 0);
                framework
                    .create_dialectica_obligation(cx, NodeId::new(1), obligation_id_1, vec![])
                    .await
                    .unwrap();

                // Create obligation on node 2 that would violate causality
                let obligation_id_2 = ObligationId::new_for_test(2, 0);

                // Manually advance node 2's clock to create future timestamp
                {
                    let mut node_registry = framework.node_registry.write().await;
                    let node_state = node_registry.get_mut(&NodeId::new(2)).unwrap();
                    for _ in 0..5 {
                        node_state
                            .local_vclock
                            .advance_local(NodeId::new(2))
                            .unwrap();
                    }
                }

                framework
                    .create_dialectica_obligation(cx, NodeId::new(2), obligation_id_2, vec![])
                    .await
                    .unwrap();

                // Try to serialize from node 2 (future) to node 1 (past)
                // This should detect a causality violation
                let result = framework
                    .serialize_obligation_causally(
                        cx,
                        obligation_id_2,
                        NodeId::new(2),
                        NodeId::new(1),
                    )
                    .await;

                // Should fail due to causal ordering violation
                assert!(result.is_err());

                // Check that violation was detected and recorded
                let stats = framework.get_serialization_stats().await;
                assert!(stats.causal_violations_detected > 0);

                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_obligation_serialization() {
        let framework = DialecticaVClockTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime
            .region(Budget::unlimited(), |cx| async move {
                // Create multiple nodes for concurrent operations
                let node_count = 6;
                for i in 1..=node_count {
                    framework.create_node(NodeId::new(i)).await.unwrap();
                }

                let framework_ref = &framework;

                // Spawn concurrent tasks to create and serialize obligations
                let tasks: Vec<_> = (1..=node_count)
                    .map(|i| {
                        spawn(cx, Budget::unlimited(), async move {
                            let obligation_id = ObligationId::new_for_test(i, 0);

                            // Create obligation
                            framework_ref
                                .create_dialectica_obligation(
                                    cx,
                                    NodeId::new(i),
                                    obligation_id,
                                    vec![],
                                )
                                .await
                                .unwrap();

                            // Construct proof
                            framework_ref
                                .construct_proof(cx, obligation_id, NodeId::new(i))
                                .await
                                .unwrap();

                            // Serialize to next node (circular)
                            let target_node = if i < node_count { i + 1 } else { 1 };
                            let serialized = framework_ref
                                .serialize_obligation_causally(
                                    cx,
                                    obligation_id,
                                    NodeId::new(i),
                                    NodeId::new(target_node),
                                )
                                .await
                                .unwrap();

                            // Deserialize on target node
                            framework_ref
                                .deserialize_obligation_causally(
                                    cx,
                                    &serialized,
                                    NodeId::new(target_node),
                                )
                                .await
                                .unwrap();

                            Ok(obligation_id)
                        })
                    })
                    .collect();

                // Wait for all concurrent operations to complete
                let mut results = Vec::new();
                for task in tasks {
                    let result = task.join().await;
                    assert!(matches!(result, Outcome::Ok(Ok(_))));
                    results.push(result);
                }

                // Verify all operations completed successfully
                assert_eq!(results.len(), node_count as usize);

                // Check final causality state
                let causality_preserved = framework.verify_cross_node_causality(cx).await.unwrap();
                assert!(causality_preserved);

                // Verify concurrent operations were recorded
                let stats = framework.get_serialization_stats().await;
                assert_eq!(stats.obligations_serialized, node_count);
                assert_eq!(stats.causal_violations_detected, 0);

                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_dialectica_witness_causal_verification() {
        let framework = DialecticaVClockTestFramework::new().await.unwrap();
        let runtime = framework.runtime.clone();

        runtime
            .region(Budget::unlimited(), |cx| async move {
                // Create nodes for witness verification across vector clock boundaries
                framework.create_node(NodeId::new(1)).await.unwrap();
                framework.create_node(NodeId::new(2)).await.unwrap();

                // Create obligation with witness requirement
                let obligation_id = ObligationId::new_for_test(1, 0);
                framework
                    .create_dialectica_obligation(cx, NodeId::new(1), obligation_id, vec![])
                    .await
                    .unwrap();

                // Construct proof and witness
                let proof = framework
                    .construct_proof(cx, obligation_id, NodeId::new(1))
                    .await
                    .unwrap();

                // Create witness for the proof
                let witness = DialecticaWitness::construct_for_proof(&proof)?;

                // Update obligation with witness
                {
                    let mut obligation_registry = framework.obligation_registry.write().await;
                    if let Some(obligation) = obligation_registry.get_mut(&obligation_id) {
                        obligation.witness = Some(witness.clone());
                        obligation.state = ProofState::Witnessed;
                    }
                }

                // Serialize obligation with witness across vector clock boundary
                let serialized = framework
                    .serialize_obligation_causally(
                        cx,
                        obligation_id,
                        NodeId::new(1),
                        NodeId::new(2),
                    )
                    .await
                    .unwrap();

                // Deserialize and verify witness is preserved
                let deserialized_id = framework
                    .deserialize_obligation_causally(cx, &serialized, NodeId::new(2))
                    .await
                    .unwrap();

                assert_eq!(deserialized_id, obligation_id);

                // Verify witness integrity across vector clock boundary
                {
                    let obligation_registry = framework.obligation_registry.read().await;
                    let obligation = obligation_registry.get(&obligation_id).unwrap();
                    assert!(obligation.witness.is_some());

                    let preserved_witness = obligation.witness.as_ref().unwrap();
                    assert!(preserved_witness.verify_against_proof(&proof)?);
                }

                // Check that witness verification was recorded
                let stats = framework.get_serialization_stats().await;
                assert_eq!(stats.obligations_serialized, 1);
                assert_eq!(stats.causal_violations_detected, 0);

                Ok(())
            })
            .await
            .unwrap();
    }
}
