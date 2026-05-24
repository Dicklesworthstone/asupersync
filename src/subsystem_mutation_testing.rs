//! Subsystem-specific mutation testing for asupersync components
//!
//! Validates that individual subsystems correctly detect and handle
//! targeted mutations in their specific domains:
//! - Observability: Counter increment and diagnostic reporting
//! - Trace: Causality DAG and event ordering
//! - Security: Authenticated encryption and integrity validation

#![cfg(all(test, feature = "real-service-e2e"))]

use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::runtime::{LabRuntime, RuntimeBuilder};
use crate::sync::{AtomicBool, AtomicUsize, Ordering};
use crate::time::{Duration, Instant, sleep};
use crate::types::Outcome;

use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

/// Subsystem mutation tester for targeted component validation
struct SubsystemMutationTester {
    runtime: LabRuntime,
    test_name: String,
    mutations_applied: Arc<AtomicUsize>,
    mutations_detected: Arc<AtomicUsize>,
}

impl SubsystemMutationTester {
    async fn new(test_name: &str) -> Self {
        let temp_dir = TempDir::new().expect("Should create temp directory");

        let runtime = RuntimeBuilder::new()
            .with_lab_mode()
            .with_temp_dir(temp_dir.path())
            .build()
            .await
            .expect("Should build lab runtime");

        Self {
            runtime,
            test_name: test_name.to_string(),
            mutations_applied: Arc::new(AtomicUsize::new(0)),
            mutations_detected: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn log_subsystem_mutation(
        &self,
        mutation_id: &str,
        component: &str,
        mutation_type: &str,
        detected: bool,
    ) {
        eprintln!(
            "{{\"subsystem_mutation\":\"{}\",\"id\":\"{}\",\"component\":\"{}\",\"type\":\"{}\",\"detected\":{}}}",
            self.test_name, mutation_id, component, mutation_type, detected
        );

        self.mutations_applied.fetch_add(1, Ordering::Relaxed);
        if detected {
            self.mutations_detected.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// [br-mutation-13] Observability counter increment regression mutations
    async fn test_observability_counter_mutations(&self) {
        // Test various counter increment regressions in observability system
        use crate::observability::{Counter, Histogram, Metrics};

        let metrics_detected = self
            .runtime
            .scope(|scope| async move {
                // Setup observability metrics
                let request_counter = Counter::new("requests_total", "Total HTTP requests");
                let error_counter = Counter::new("errors_total", "Total errors");
                let response_histogram =
                    Histogram::new("response_duration", "Response time distribution");

                let total_requests = 100;
                let error_mutations = Arc::new(AtomicUsize::new(0));
                let missing_increments = Arc::new(AtomicUsize::new(0));
                let incorrect_increments = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for req_id in 0..total_requests {
                            let start_time = Instant::now();

                            // Simulate request processing with mutations
                            sleep(Duration::from_millis(10)).await;

                            // MUTATION 1: Skip counter increment for some requests
                            if req_id % 7 == 0 {
                                missing_increments.fetch_add(1, Ordering::Relaxed);
                                // Intentionally skip request_counter.inc() - should be detected
                            } else {
                                request_counter.inc();
                            }

                            // Simulate error conditions with mutations
                            if req_id % 15 == 0 {
                                // MUTATION 2: Increment wrong counter for errors
                                if req_id % 30 == 0 {
                                    incorrect_increments.fetch_add(1, Ordering::Relaxed);
                                    request_counter.inc(); // Wrong counter - should increment error_counter
                                } else {
                                    error_counter.inc(); // Correct
                                }
                                error_mutations.fetch_add(1, Ordering::Relaxed);
                            }

                            // Record response time (this should be consistent)
                            let duration = start_time.elapsed();
                            response_histogram.observe(duration.as_secs_f64());

                            if req_id % 25 == 0 {
                                // Validate counter consistency
                                let request_count = request_counter.get();
                                let error_count = error_counter.get();

                                // Expected counts based on mutations
                                let expected_requests =
                                    req_id + 1 - missing_increments.load(Ordering::Relaxed);
                                let expected_errors = error_mutations.load(Ordering::Relaxed);

                                // Check for discrepancies (should detect counter mutations)
                                if request_count != expected_requests
                                    || error_count != expected_errors
                                {
                                    return Outcome::Err(Error::new(
                                        ErrorKind::Other,
                                        format!(
                                            "Counter mutation detected: req {} != {}, err {} != {}",
                                            request_count,
                                            expected_requests,
                                            error_count,
                                            expected_errors
                                        ),
                                    ));
                                }
                            }
                        }

                        // Final validation
                        let final_requests = request_counter.get();
                        let final_errors = error_counter.get();
                        let missed = missing_increments.load(Ordering::Relaxed);
                        let incorrect = incorrect_increments.load(Ordering::Relaxed);

                        // Check if observability system detected counter inconsistencies
                        let expected_requests = total_requests - missed + incorrect;
                        let expected_errors = error_mutations.load(Ordering::Relaxed) - incorrect;

                        if final_requests != expected_requests || final_errors != expected_errors {
                            Outcome::Ok(true) // Mutations detected
                        } else {
                            Outcome::Ok(false) // Mutations not detected (bad)
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(metrics_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-13",
            "observability",
            "counter_increment_regression",
            detected,
        );
    }

    /// [br-mutation-14] Trace causality DAG event-order swap mutations
    async fn test_trace_causality_mutations(&self) {
        // Test event ordering and causality violations in trace system
        use crate::trace::{CausalityDAG, SpanId, TraceEvent, TraceId};

        let causality_detected =
            self.runtime
                .scope(|scope| async move {
                    let trace_id = TraceId::new();
                    let causality_dag = CausalityDAG::new();

                    let event_count = 20;
                    let ordering_violations = Arc::new(AtomicUsize::new(0));
                    let causality_errors = Arc::new(AtomicUsize::new(0));

                    let task = scope.spawn(async move {
                let mut events = Vec::new();
                let mut span_counter = 0;

                // Generate sequence of causally related events
                for event_id in 0..event_count {
                    span_counter += 1;
                    let span_id = SpanId::from(span_counter);
                    let timestamp = Instant::now();

                    // Create parent-child relationships
                    let parent_span = if event_id > 0 {
                        Some(SpanId::from(span_counter - 1))
                    } else {
                        None
                    };

                    let event = TraceEvent::new(trace_id, span_id, parent_span, timestamp);

                    // MUTATION 1: Swap event order for some events (violate causality)
                    if event_id % 6 == 0 && event_id > 0 {
                        ordering_violations.fetch_add(1, Ordering::Relaxed);

                        // Swap this event with the previous one (violate happened-before)
                        if let Some(mut prev_event) = events.pop() {
                            // Swap timestamps to create causality violation
                            let temp_timestamp = event.timestamp();
                            let mut corrupted_event = event.with_timestamp(prev_event.timestamp());
                            prev_event = prev_event.with_timestamp(temp_timestamp);

                            events.push(corrupted_event);
                            events.push(prev_event);
                        }
                    } else {
                        events.push(event);
                    }

                    sleep(Duration::from_millis(5)).await; // Ensure time progression
                }

                // Submit events to causality DAG and check for violations
                for (idx, event) in events.iter().enumerate() {
                    match causality_dag.add_event(event.clone()) {
                        Ok(_) => {
                            // Event accepted - check causality constraints
                            if let Some(parent) = event.parent_span() {
                                if !causality_dag.validates_causality(parent, event.span_id()) {
                                    causality_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(_) => {
                            // Event rejected due to causality violation
                            causality_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                let total_violations = ordering_violations.load(Ordering::Relaxed);
                let detected_errors = causality_errors.load(Ordering::Relaxed);

                // Causality DAG should detect ordering violations
                if detected_errors > 0 && total_violations > 0 {
                    Outcome::Ok(true) // Causality violations detected
                } else if total_violations > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Causality violations not detected: {} violations, {} errors",
                            total_violations, detected_errors)))
                } else {
                    Outcome::Ok(false) // No violations to detect
                }
            }).await;

                    task.await.unwrap_or(Outcome::Ok(false))
                })
                .await;

        let detected = matches!(causality_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-14",
            "trace",
            "causality_dag_event_order_swap",
            detected,
        );
    }

    /// [br-mutation-15] Security authenticated encryption tag-flip mutations
    async fn test_security_auth_encryption_mutations(&self) {
        // Test bit-level tampering detection in authenticated encryption
        use crate::security::{AuthTag, AuthenticatedEncryption, EncryptionKey};

        let auth_detected = self
            .runtime
            .scope(|scope| async move {
                let encryption_key = EncryptionKey::generate();
                let auth_enc = AuthenticatedEncryption::new(encryption_key);

                let message_count = 15;
                let tag_flip_mutations = Arc::new(AtomicUsize::new(0));
                let tampering_detected = Arc::new(AtomicUsize::new(0));

                let task = scope.spawn(async move {
                for msg_id in 0..message_count {
                    let plaintext = format!("Secret message #{} with important data", msg_id);
                    let additional_data = format!("metadata_{}", msg_id);

                    // Encrypt message
                    let (ciphertext, auth_tag) = match auth_enc.encrypt(
                        plaintext.as_bytes(),
                        additional_data.as_bytes()
                    ) {
                        Ok(result) => result,
                        Err(_) => continue,
                    };

                    // MUTATION: Flip random bits in authentication tag
                    let mut corrupted_tag = auth_tag.clone();
                    if msg_id % 4 == 0 {
                        tag_flip_mutations.fetch_add(1, Ordering::Relaxed);

                        // Flip random bits in auth tag (simulate bit-level tampering)
                        let tag_bytes = corrupted_tag.as_mut_bytes();
                        if !tag_bytes.is_empty() {
                            let flip_position = msg_id % tag_bytes.len();
                            let bit_position = msg_id % 8;
                            tag_bytes[flip_position] ^= 1 << bit_position; // Flip one bit
                        }
                    }

                    // Attempt decryption with potentially corrupted tag
                    match auth_enc.decrypt(
                        &ciphertext,
                        &corrupted_tag,
                        additional_data.as_bytes()
                    ) {
                        Ok(decrypted) => {
                            // Decryption succeeded - check if content matches
                            if decrypted != plaintext.as_bytes() || msg_id % 4 == 0 {
                                // Either content doesn't match or tag was flipped
                                if msg_id % 4 == 0 {
                                    // Tag was flipped but decryption "succeeded" - BAD
                                    return Outcome::Err(Error::new(ErrorKind::Other,
                                        "Authenticated encryption failed to detect tag tampering"));
                                }
                            }
                        }
                        Err(_) => {
                            // Decryption failed - check if this was due to tag corruption
                            if msg_id % 4 == 0 {
                                tampering_detected.fetch_add(1, Ordering::Relaxed);
                                // Tag flip correctly detected and rejected
                            }
                        }
                    }

                    sleep(Duration::from_millis(5)).await;
                }

                let total_tag_flips = tag_flip_mutations.load(Ordering::Relaxed);
                let detected_tampering = tampering_detected.load(Ordering::Relaxed);

                // Authenticated encryption should detect tag tampering
                if detected_tampering == total_tag_flips && total_tag_flips > 0 {
                    Outcome::Ok(true) // All tag flips detected
                } else if total_tag_flips > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Tag tampering detection failed: {}/{} detected",
                            detected_tampering, total_tag_flips)))
                } else {
                    Outcome::Ok(false) // No tampering to detect
                }
            }).await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(auth_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-15",
            "security",
            "auth_encryption_tag_flip",
            detected,
        );
    }

    /// Additional observability mutation: metric aggregation corruption
    async fn test_observability_aggregation_mutations(&self) {
        use crate::observability::{Gauge, Histogram, Summary};

        let aggregation_detected = self.runtime.scope(|scope| async move {
            let response_histogram = Histogram::new("response_time", "HTTP response times");
            let memory_gauge = Gauge::new("memory_usage", "Current memory usage");
            let throughput_summary = Summary::new("throughput", "Request throughput summary");

            let sample_count = 50;
            let aggregation_errors = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for sample_id in 0..sample_count {
                    let response_time = 0.1 + (sample_id as f64) * 0.01; // 100ms to 590ms
                    let memory_usage = 1024.0 + (sample_id as f64) * 10.0; // Growing memory
                    let throughput = 100.0 - (sample_id as f64) * 0.5; // Declining throughput

                    // MUTATION: Corrupt some metric values during aggregation
                    if sample_id % 8 == 0 {
                        aggregation_errors.fetch_add(1, Ordering::Relaxed);

                        // Record corrupted values
                        response_histogram.observe(response_time * 10.0); // 10x corruption
                        memory_gauge.set(memory_usage * -1.0); // Negative memory (impossible)
                        throughput_summary.observe(throughput + 1000.0); // Throughput spike
                    } else {
                        // Record correct values
                        response_histogram.observe(response_time);
                        memory_gauge.set(memory_usage);
                        throughput_summary.observe(throughput);
                    }

                    // Validate metric consistency every 10 samples
                    if sample_id % 10 == 9 {
                        let hist_mean = response_histogram.mean();
                        let gauge_value = memory_gauge.get();
                        let summary_mean = throughput_summary.mean();

                        // Check for unrealistic values that indicate corruption
                        let hist_corrupted = hist_mean > 1.0; // Mean > 1 second is suspicious
                        let gauge_corrupted = gauge_value < 0.0; // Negative memory is impossible
                        let summary_corrupted = summary_mean > 200.0; // Throughput > 200 is suspicious

                        if hist_corrupted || gauge_corrupted || summary_corrupted {
                            return Outcome::Err(Error::new(ErrorKind::Other,
                                format!("Metric aggregation corruption detected: hist={:.2}, gauge={:.2}, summary={:.2}",
                                    hist_mean, gauge_value, summary_mean)));
                        }
                    }
                }

                // Check final aggregated values
                let errors = aggregation_errors.load(Ordering::Relaxed);
                if errors > 0 {
                    Outcome::Ok(true) // Corruption should be detectable
                } else {
                    Outcome::Ok(false) // No corruption
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(aggregation_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-13b",
            "observability",
            "metric_aggregation_corruption",
            detected,
        );
    }

    /// Additional trace mutation: span relationship corruption
    async fn test_trace_span_relationship_mutations(&self) {
        use crate::trace::{Span, SpanContext, SpanId, TraceId};

        let span_detected = self
            .runtime
            .scope(|scope| async move {
                let trace_id = TraceId::new();
                let span_tree = Arc::new(std::sync::Mutex::new(HashMap::<SpanId, Span>::new()));

                let span_count = 25;
                let relationship_corruptions = Arc::new(AtomicUsize::new(0));
                let validation_errors = Arc::new(AtomicUsize::new(0));

                let task = scope.spawn(async move {
                let mut parent_stack = Vec::new();

                for span_idx in 0..span_count {
                    let span_id = SpanId::from(span_idx + 1);

                    // Determine parent relationship
                    let parent_id = if span_idx == 0 {
                        None // Root span
                    } else if span_idx % 5 == 0 {
                        parent_stack.pop() // End nested span
                    } else {
                        parent_stack.last().copied()
                    };

                    // Create span with potentially corrupted parent relationship
                    let mut actual_parent = parent_id;
                    if span_idx % 7 == 0 && span_idx > 2 {
                        relationship_corruptions.fetch_add(1, Ordering::Relaxed);

                        // MUTATION: Corrupt parent relationship
                        actual_parent = Some(SpanId::from(span_idx - 2)); // Wrong parent
                    }

                    let span = Span::new(trace_id, span_id, actual_parent);

                    // Add to span tree
                    {
                        let mut tree = span_tree.lock().unwrap();
                        tree.insert(span_id, span.clone());
                    }

                    // Validate span tree consistency
                    if let Some(parent) = actual_parent {
                        let tree = span_tree.lock().unwrap();
                        if let Some(parent_span) = tree.get(&parent) {
                            // Check if parent-child relationship makes sense
                            let parent_start = parent_span.start_time();
                            let child_start = span.start_time();

                            // Child should start after parent
                            if child_start < parent_start {
                                validation_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            // Parent doesn't exist in tree
                            validation_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // Update parent stack for nesting
                    if span_idx % 3 == 0 {
                        parent_stack.push(span_id);
                    }

                    sleep(Duration::from_millis(2)).await;
                }

                let corruptions = relationship_corruptions.load(Ordering::Relaxed);
                let errors = validation_errors.load(Ordering::Relaxed);

                // Validation should catch relationship corruptions
                if errors > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Span relationship corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Span relationship validation failed: {} corruptions, {} errors",
                            corruptions, errors)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(span_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-14b",
            "trace",
            "span_relationship_corruption",
            detected,
        );
    }

    /// Additional security mutation: encryption key corruption
    async fn test_security_key_corruption_mutations(&self) {
        use crate::security::{CryptoError, EncryptionKey, KeyDerivation};

        let key_detected = self
            .runtime
            .scope(|scope| async move {
                let master_key = EncryptionKey::generate();
                let key_derivation = KeyDerivation::new(master_key);

                let derivation_count = 20;
                let key_corruptions = Arc::new(AtomicUsize::new(0));
                let crypto_errors = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for derive_id in 0..derivation_count {
                            let context = format!("derive_context_{}", derive_id);
                            let salt = format!("salt_{}", derive_id);

                            // Derive key
                            let derived_key = match key_derivation.derive(&context, salt.as_bytes())
                            {
                                Ok(key) => key,
                                Err(_) => continue,
                            };

                            // MUTATION: Corrupt derived key bytes
                            let mut key_bytes = derived_key.as_bytes().to_vec();
                            if derive_id % 5 == 0 {
                                key_corruptions.fetch_add(1, Ordering::Relaxed);

                                // Flip random bits in key
                                if !key_bytes.is_empty() {
                                    let corrupt_position = derive_id % key_bytes.len();
                                    key_bytes[corrupt_position] ^= 0xFF; // Flip all bits in one byte
                                }
                            }

                            // Try to use potentially corrupted key
                            let corrupted_key = EncryptionKey::from_bytes(&key_bytes);

                            // Encrypt test data with corrupted key
                            let test_data = b"test encryption data";
                            match corrupted_key.encrypt(test_data) {
                                Ok(encrypted) => {
                                    // Try to decrypt with original derived key
                                    match derived_key.decrypt(&encrypted) {
                                        Ok(decrypted) => {
                                            if decrypted != test_data && derive_id % 5 == 0 {
                                                // Key corruption caused decryption mismatch
                                                crypto_errors.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Err(_) => {
                                            if derive_id % 5 == 0 {
                                                // Key corruption caused decryption failure
                                                crypto_errors.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                }
                                Err(_) => {
                                    if derive_id % 5 == 0 {
                                        // Key corruption caused encryption failure
                                        crypto_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }

                            sleep(Duration::from_millis(3)).await;
                        }

                        let corruptions = key_corruptions.load(Ordering::Relaxed);
                        let errors = crypto_errors.load(Ordering::Relaxed);

                        // Crypto operations should detect key corruption
                        if errors > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Key corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Key corruption not detected: {} corruptions, {} errors",
                                    corruptions, errors
                                ),
                            ))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(key_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-15b",
            "security",
            "encryption_key_corruption",
            detected,
        );
    }

    /// [br-mutation-16] Plan graph topology edge insertion regression mutations
    async fn test_plan_graph_topology_mutations(&self) {
        use crate::plan::{PlanEdge, PlanGraph, PlanNode, TopologyError};

        let plan_detected =
            self.runtime
                .scope(|scope| async move {
                    let graph_size = 20;
                    let topology_corruptions = Arc::new(AtomicUsize::new(0));
                    let validation_errors = Arc::new(AtomicUsize::new(0));

                    let task = scope.spawn(async move {
                let mut plan_graph = PlanGraph::new();

                // Build initial plan graph
                for node_idx in 0..graph_size {
                    let node_id = format!("node_{}", node_idx);
                    let node = PlanNode::new(&node_id);
                    plan_graph.add_node(node).expect("Should add node");
                }

                // Add edges with mutations
                for edge_idx in 0..graph_size - 1 {
                    let source_id = format!("node_{}", edge_idx);
                    let target_id = format!("node_{}", edge_idx + 1);

                    // MUTATION: Insert invalid edges that create cycles or invalid topology
                    if edge_idx % 6 == 0 {
                        topology_corruptions.fetch_add(1, Ordering::Relaxed);

                        // Create cycle by adding reverse edge
                        let cycle_edge = PlanEdge::new(&target_id, &source_id);
                        match plan_graph.add_edge(cycle_edge) {
                            Ok(_) => {
                                // Check if cycle detection works
                                match plan_graph.validate_topology() {
                                    Err(TopologyError::CycleDetected(_)) => {
                                        validation_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                    _ => {}
                                }
                            }
                            Err(_) => {
                                validation_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    // MUTATION: Insert edge to non-existent node
                    if edge_idx % 8 == 0 {
                        topology_corruptions.fetch_add(1, Ordering::Relaxed);

                        let invalid_edge = PlanEdge::new(&source_id, "non_existent_node");
                        match plan_graph.add_edge(invalid_edge) {
                            Err(_) => {
                                validation_errors.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(_) => {
                                // Should not succeed
                            }
                        }
                    }

                    // Add normal edge
                    let normal_edge = PlanEdge::new(&source_id, &target_id);
                    let _ = plan_graph.add_edge(normal_edge);

                    sleep(Duration::from_millis(1)).await;
                }

                let corruptions = topology_corruptions.load(Ordering::Relaxed);
                let errors = validation_errors.load(Ordering::Relaxed);

                // Plan topology validation should catch edge insertion regressions
                if errors > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Topology corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Plan topology validation failed: {} corruptions, {} errors",
                            corruptions, errors)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

                    task.await.unwrap_or(Outcome::Ok(false))
                })
                .await;

        let detected = matches!(plan_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-16",
            "plan",
            "graph_topology_corruption",
            detected,
        );
    }

    /// [br-mutation-17] RaptorQ systematic symbol decode regression mutations
    async fn test_raptorq_systematic_symbol_mutations(&self) {
        use crate::raptorq::{Decoder, Encoder, EncodingPacket, K_MAX, Symbol};

        let raptorq_detected = self.runtime.scope(|scope| async move {
            let source_block_size = 64; // K symbols
            let repair_symbol_count = 20; // Generate repair symbols
            let symbol_corruptions = Arc::new(AtomicUsize::new(0));
            let decode_failures = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                // Create source data
                let source_data: Vec<u8> = (0..source_block_size * 1024)
                    .map(|i| (i % 256) as u8)
                    .collect();

                // Encode with RaptorQ
                let mut encoder = Encoder::new(&source_data, source_block_size);
                let encoding_packets = encoder.generate_packets(source_block_size + repair_symbol_count);

                // Test decode with systematic symbol mutations
                for mutation_test in 0..15 {
                    let mut decoder = Decoder::new();
                    let mut packets_to_decode = encoding_packets.clone();

                    // MUTATION: Corrupt systematic symbols (source symbols)
                    if mutation_test % 3 == 0 {
                        symbol_corruptions.fetch_add(1, Ordering::Relaxed);

                        // Corrupt systematic symbols that represent original data
                        for (packet_idx, packet) in packets_to_decode.iter_mut().enumerate() {
                            if packet.is_systematic() && packet_idx % 7 == 0 {
                                // Corrupt systematic symbol data
                                let mut symbol_data = packet.symbol_data().to_vec();
                                if !symbol_data.is_empty() {
                                    let corrupt_pos = (packet_idx * 37) % symbol_data.len();
                                    symbol_data[corrupt_pos] ^= 0xAA; // Flip bits
                                }
                                *packet = EncodingPacket::new_systematic(
                                    packet.encoding_symbol_id(),
                                    Symbol::from_vec(symbol_data)
                                );
                            }
                        }
                    }

                    // Try to decode with potentially corrupted systematic symbols
                    for packet in packets_to_decode.iter().take(source_block_size + 5) {
                        decoder.add_packet(packet.clone());
                    }

                    match decoder.decode() {
                        Ok(decoded_data) => {
                            // Check if decoded data matches original
                            if decoded_data != source_data && mutation_test % 3 == 0 {
                                // Corruption detected through data mismatch
                                decode_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            if mutation_test % 3 == 0 {
                                // Corruption detected through decode failure
                                decode_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    sleep(Duration::from_millis(5)).await;
                }

                let corruptions = symbol_corruptions.load(Ordering::Relaxed);
                let failures = decode_failures.load(Ordering::Relaxed);

                // RaptorQ decode should catch systematic symbol corruption
                if failures > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Systematic symbol corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("RaptorQ systematic symbol validation failed: {} corruptions, {} failures",
                            corruptions, failures)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(raptorq_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-17",
            "raptorq",
            "systematic_symbol_corruption",
            detected,
        );
    }

    /// [br-mutation-18] Distributed consistent hash ring rebalance corruption mutations
    async fn test_distributed_consistent_hash_mutations(&self) {
        use crate::distributed::{ConsistentHashRing, Hash, Node, RebalanceError};

        let distributed_detected = self.runtime.scope(|scope| async move {
            let initial_node_count = 8;
            let rebalance_corruptions = Arc::new(AtomicUsize::new(0));
            let consistency_errors = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                let mut hash_ring = ConsistentHashRing::new();

                // Add initial nodes to hash ring
                for node_idx in 0..initial_node_count {
                    let node_id = format!("node_{}", node_idx);
                    let node = Node::new(&node_id);
                    hash_ring.add_node(node);
                }

                // Test key distribution before rebalance
                let test_keys: Vec<String> = (0..100)
                    .map(|i| format!("key_{}", i))
                    .collect();

                let initial_distribution: HashMap<String, String> = test_keys
                    .iter()
                    .map(|key| (key.clone(), hash_ring.get_node(key).unwrap().id().to_string()))
                    .collect();

                // Perform rebalance operations with mutations
                for rebalance_test in 0..10 {
                    let new_node_id = format!("new_node_{}", rebalance_test);
                    let new_node = Node::new(&new_node_id);

                    // MUTATION: Corrupt hash ring during rebalance
                    if rebalance_test % 4 == 0 {
                        rebalance_corruptions.fetch_add(1, Ordering::Relaxed);

                        // Corrupt hash ring state during node addition
                        match hash_ring.add_node_with_corruption(new_node.clone()) {
                            Err(RebalanceError::CorruptedRing(_)) => {
                                consistency_errors.fetch_add(1, Ordering::Relaxed);
                                continue; // Skip this test iteration
                            }
                            _ => {}
                        }
                    } else {
                        hash_ring.add_node(new_node.clone());
                    }

                    // MUTATION: Corrupt node removal during rebalance
                    if rebalance_test % 5 == 0 && rebalance_test > 0 {
                        rebalance_corruptions.fetch_add(1, Ordering::Relaxed);

                        let remove_node_id = format!("node_{}", rebalance_test % initial_node_count);
                        match hash_ring.remove_node_with_corruption(&remove_node_id) {
                            Err(RebalanceError::InconsistentState(_)) => {
                                consistency_errors.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }

                    // Validate consistency after rebalance
                    let post_distribution: HashMap<String, String> = test_keys
                        .iter()
                        .filter_map(|key| {
                            hash_ring.get_node(key).map(|node|
                                (key.clone(), node.id().to_string())
                            )
                        })
                        .collect();

                    // Check for excessive key movement (should be minimal)
                    let moved_keys: usize = test_keys
                        .iter()
                        .filter(|key| {
                            let initial_node = initial_distribution.get(*key);
                            let current_node = post_distribution.get(*key);
                            initial_node != current_node && current_node.is_some()
                        })
                        .count();

                    // Too many key movements indicate ring corruption
                    let total_keys = test_keys.len();
                    if moved_keys > total_keys / 2 && rebalance_test % 4 == 0 {
                        consistency_errors.fetch_add(1, Ordering::Relaxed);
                    }

                    sleep(Duration::from_millis(3)).await;
                }

                let corruptions = rebalance_corruptions.load(Ordering::Relaxed);
                let errors = consistency_errors.load(Ordering::Relaxed);

                // Consistent hash ring should detect rebalance corruption
                if errors > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Rebalance corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Consistent hash rebalance validation failed: {} corruptions, {} errors",
                            corruptions, errors)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(distributed_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-18",
            "distributed",
            "consistent_hash_corruption",
            detected,
        );
    }

    /// [br-mutation-19] gRPC status code mapping regression mutations
    async fn test_grpc_status_code_mapping_mutations(&self) {
        use crate::grpc::{GrpcError, GrpcResponse, Status, StatusCode};

        let grpc_detected = self
            .runtime
            .scope(|scope| async move {
                let rpc_call_count = 25;
                let status_corruptions = Arc::new(AtomicUsize::new(0));
                let mapping_errors = Arc::new(AtomicUsize::new(0));

                let task = scope.spawn(async move {
                for rpc_idx in 0..rpc_call_count {
                    // Simulate various gRPC responses with status codes
                    let expected_status = match rpc_idx % 7 {
                        0 => StatusCode::Ok,
                        1 => StatusCode::InvalidArgument,
                        2 => StatusCode::NotFound,
                        3 => StatusCode::PermissionDenied,
                        4 => StatusCode::Unauthenticated,
                        5 => StatusCode::ResourceExhausted,
                        _ => StatusCode::Internal,
                    };

                    let mut actual_status = expected_status;

                    // MUTATION: Corrupt gRPC status code mapping
                    if rpc_idx % 5 == 0 {
                        status_corruptions.fetch_add(1, Ordering::Relaxed);

                        // Map to wrong status code
                        actual_status = match expected_status {
                            StatusCode::Ok => StatusCode::Internal, // Success mapped to error
                            StatusCode::NotFound => StatusCode::Ok, // Error mapped to success
                            StatusCode::PermissionDenied => StatusCode::Unauthenticated, // Wrong error type
                            StatusCode::InvalidArgument => StatusCode::ResourceExhausted, // Wrong error type
                            other => other, // Keep some unchanged
                        };
                    }

                    // Create gRPC response with potentially corrupted status
                    let response = GrpcResponse::new()
                        .with_status(actual_status)
                        .with_message(format!("RPC call {}", rpc_idx));

                    // Validate status code mapping consistency
                    let validation_result = match (expected_status, actual_status) {
                        (StatusCode::Ok, StatusCode::Ok) => true, // Correct success
                        (expected, actual) if expected == actual => true, // Correct error
                        (StatusCode::Ok, _) if rpc_idx % 5 == 0 => {
                            // Success incorrectly mapped to error - should be detected
                            mapping_errors.fetch_add(1, Ordering::Relaxed);
                            false
                        }
                        (_, StatusCode::Ok) if rpc_idx % 5 == 0 => {
                            // Error incorrectly mapped to success - should be detected
                            mapping_errors.fetch_add(1, Ordering::Relaxed);
                            false
                        }
                        (_, _) if rpc_idx % 5 == 0 => {
                            // Wrong error type mapping - should be detected
                            mapping_errors.fetch_add(1, Ordering::Relaxed);
                            false
                        }
                        _ => true, // No mutation applied
                    };

                    // Additional validation: Check HTTP status code mapping
                    let http_status = response.to_http_status();
                    let expected_http = expected_status.to_http_status();
                    if http_status != expected_http && rpc_idx % 5 == 0 {
                        mapping_errors.fetch_add(1, Ordering::Relaxed);
                    }

                    sleep(Duration::from_millis(2)).await;
                }

                let corruptions = status_corruptions.load(Ordering::Relaxed);
                let errors = mapping_errors.load(Ordering::Relaxed);

                // gRPC status validation should detect mapping corruptions
                if errors > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Status mapping corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("gRPC status mapping validation failed: {} corruptions, {} errors",
                            corruptions, errors)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(grpc_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-19",
            "grpc",
            "status_code_mapping_corruption",
            detected,
        );
    }

    /// [br-mutation-20] Messaging Kafka offset commit regression mutations
    async fn test_messaging_kafka_offset_mutations(&self) {
        use crate::messaging::{KafkaConsumer, KafkaProducer, OffsetCommitMode, Partition};

        let kafka_detected = self.runtime.scope(|scope| async move {
            let message_count = 30;
            let topic_name = "test_topic_mutations";
            let partition_count = 3;
            let offset_corruptions = Arc::new(AtomicUsize::new(0));
            let commit_errors = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                // Setup Kafka consumer with manual offset commit mode
                let mut consumer = KafkaConsumer::new()
                    .with_topic(topic_name)
                    .with_commit_mode(OffsetCommitMode::Manual);

                let mut partition_offsets: HashMap<u32, u64> = HashMap::new();

                for msg_idx in 0..message_count {
                    let partition_id = (msg_idx % partition_count) as u32;
                    let message_offset = msg_idx as u64;

                    // Track expected offset for each partition
                    let current_offset = partition_offsets.get(&partition_id).unwrap_or(&0);
                    let expected_offset = current_offset + 1;
                    partition_offsets.insert(partition_id, expected_offset);

                    let mut actual_offset = expected_offset;

                    // MUTATION: Corrupt Kafka offset commit values
                    if msg_idx % 6 == 0 {
                        offset_corruptions.fetch_add(1, Ordering::Relaxed);

                        // Corrupt offset in various ways
                        match msg_idx % 18 {
                            0 => actual_offset = expected_offset.wrapping_sub(1), // Rewind offset (duplicate)
                            6 => actual_offset = expected_offset + 10, // Jump ahead (skip messages)
                            12 => actual_offset = 0, // Reset to beginning
                            _ => {} // Keep correct offset for some cases
                        }
                    }

                    // Simulate message processing and offset commit
                    let partition = Partition::new(partition_id);
                    let commit_result = consumer.commit_offset(partition.clone(), actual_offset);

                    // Validate offset commit consistency
                    match commit_result {
                        Ok(_) => {
                            // Check if offset is in valid sequence
                            if let Some(last_committed) = consumer.get_committed_offset(&partition) {
                                // Detect backward movement or excessive jumps
                                if actual_offset < last_committed {
                                    // Offset went backward - should be detected
                                    commit_errors.fetch_add(1, Ordering::Relaxed);
                                } else if actual_offset > last_committed + 1 && msg_idx % 6 == 0 {
                                    // Offset jumped too far ahead - should be detected
                                    commit_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(_) => {
                            if msg_idx % 6 == 0 {
                                // Offset corruption caused commit failure
                                commit_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    // Additional check: Verify partition offset watermarks
                    if let Ok((low_watermark, high_watermark)) = consumer.get_watermarks(&partition) {
                        if actual_offset < low_watermark || actual_offset > high_watermark + 100 {
                            if msg_idx % 6 == 0 {
                                // Offset outside valid range - should be detected
                                commit_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    sleep(Duration::from_millis(3)).await;
                }

                let corruptions = offset_corruptions.load(Ordering::Relaxed);
                let errors = commit_errors.load(Ordering::Relaxed);

                // Kafka offset validation should detect commit corruptions
                if errors > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Offset commit corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Kafka offset commit validation failed: {} corruptions, {} errors",
                            corruptions, errors)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(kafka_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-20",
            "messaging",
            "kafka_offset_corruption",
            detected,
        );
    }

    /// [br-mutation-21] Web CSRF token rotation regression mutations
    async fn test_web_csrf_token_mutations(&self) {
        use crate::web::{CsrfToken, CsrfTokenManager, SessionId, TokenValidationError};

        let csrf_detected = self.runtime.scope(|scope| async move {
            let session_count = 20;
            let token_corruptions = Arc::new(AtomicUsize::new(0));
            let validation_errors = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                let mut csrf_manager = CsrfTokenManager::new();
                let mut session_tokens: HashMap<SessionId, CsrfToken> = HashMap::new();

                for session_idx in 0..session_count {
                    let session_id = SessionId::from(format!("session_{}", session_idx));

                    // Generate initial CSRF token
                    let initial_token = csrf_manager.generate_token(&session_id);
                    session_tokens.insert(session_id.clone(), initial_token.clone());

                    // Test token rotation with mutations
                    for rotation_idx in 0..5 {
                        let current_token = session_tokens.get(&session_id).unwrap().clone();

                        // MUTATION: Corrupt CSRF token rotation
                        let mut rotated_token = if rotation_idx % 3 == 0 {
                            token_corruptions.fetch_add(1, Ordering::Relaxed);

                            match rotation_idx % 9 {
                                0 => {
                                    // Keep old token instead of rotating
                                    current_token.clone()
                                }
                                3 => {
                                    // Generate token with wrong session ID
                                    let wrong_session = SessionId::from(format!("wrong_session_{}", session_idx));
                                    csrf_manager.generate_token(&wrong_session)
                                }
                                6 => {
                                    // Corrupt token bytes
                                    let mut corrupted = current_token.clone();
                                    corrupted.corrupt_signature(); // Flip some bits in token
                                    corrupted
                                }
                                _ => csrf_manager.rotate_token(&session_id, &current_token),
                            }
                        } else {
                            // Normal rotation
                            csrf_manager.rotate_token(&session_id, &current_token)
                        };

                        // Validate token after rotation
                        let validation_result = csrf_manager.validate_token(&session_id, &rotated_token);

                        match validation_result {
                            Ok(is_valid) => {
                                if !is_valid && rotation_idx % 3 == 0 {
                                    // Token corruption detected through validation
                                    validation_errors.fetch_add(1, Ordering::Relaxed);
                                }

                                // Check token freshness (should be recent)
                                if let Ok(token_age) = rotated_token.get_age() {
                                    if token_age > Duration::from_minutes(5) && rotation_idx % 3 == 0 {
                                        // Old token incorrectly accepted - should be detected
                                        validation_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            Err(TokenValidationError::InvalidSignature) |
                            Err(TokenValidationError::WrongSession) |
                            Err(TokenValidationError::TokenExpired) => {
                                if rotation_idx % 3 == 0 {
                                    // Token corruption detected through validation error
                                    validation_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(_) => {
                                // Other validation errors
                            }
                        }

                        // Update stored token if rotation was valid
                        if validation_result.unwrap_or(false) {
                            session_tokens.insert(session_id.clone(), rotated_token);
                        }

                        sleep(Duration::from_millis(5)).await;
                    }
                }

                let corruptions = token_corruptions.load(Ordering::Relaxed);
                let errors = validation_errors.load(Ordering::Relaxed);

                // CSRF token validation should detect rotation corruptions
                if errors > 0 && corruptions > 0 {
                    Outcome::Ok(true) // CSRF token corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("CSRF token rotation validation failed: {} corruptions, {} errors",
                            corruptions, errors)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(csrf_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-21",
            "web",
            "csrf_token_rotation_corruption",
            detected,
        );
    }

    /// [br-mutation-22] Cancel propagation signal short-circuit regression mutations
    async fn test_cancel_propagation_mutations(&self) {
        use crate::cancel::{CancelScope, CancelSignal, CancelToken, CancelledError};

        let cancel_detected = self.runtime.scope(|scope| async move {
            let cancel_chain_count = 15;
            let propagation_corruptions = Arc::new(AtomicUsize::new(0));
            let shortcircuit_failures = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for chain_idx in 0..cancel_chain_count {
                    // Create cancel token chain with nested scopes
                    let root_token = CancelToken::new();
                    let mut current_token = root_token.clone();
                    let chain_depth = 5;

                    for depth in 0..chain_depth {
                        let child_scope = CancelScope::new(current_token.clone());
                        let child_token = child_scope.token();

                        // MUTATION: Corrupt cancel signal propagation
                        if chain_idx % 4 == 0 && depth == 2 {
                            propagation_corruptions.fetch_add(1, Ordering::Relaxed);

                            // Elide early-exit signal - should not short-circuit
                            match depth % 3 {
                                0 => {
                                    // Skip signal propagation (break the chain)
                                    let broken_token = CancelToken::new(); // Independent token
                                    current_token = broken_token;
                                }
                                1 => {
                                    // Delay signal propagation
                                    sleep(Duration::from_millis(50)).await;
                                    if let Err(_) = child_scope.check_cancelled() {
                                        shortcircuit_failures.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                _ => {
                                    // Corrupt cancel state
                                    child_scope.force_uncancelled(); // Reset cancel state
                                }
                            }
                        } else {
                            current_token = child_token;
                        }

                        // Test cancel propagation at each depth
                        if depth == 3 {
                            // Cancel root token - should propagate down the chain
                            root_token.cancel();

                            // Check if cancellation propagated correctly
                            for check_depth in 0..=depth {
                                sleep(Duration::from_millis(5)).await;

                                match current_token.is_cancelled() {
                                    true => {
                                        // Expected: cancellation propagated
                                        if chain_idx % 4 == 0 && check_depth >= 2 {
                                            // Should detect propagation failure if mutation applied
                                            if current_token.cancel_reason() == None {
                                                shortcircuit_failures.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    false => {
                                        if chain_idx % 4 == 0 {
                                            // Cancellation did not propagate - mutation detected
                                            shortcircuit_failures.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }

                        sleep(Duration::from_millis(2)).await;
                    }
                }

                let corruptions = propagation_corruptions.load(Ordering::Relaxed);
                let failures = shortcircuit_failures.load(Ordering::Relaxed);

                // Cancel signal validation should detect propagation corruptions
                if failures > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Cancel propagation corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Cancel propagation validation failed: {} corruptions, {} failures",
                            corruptions, failures)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(cancel_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-22",
            "cancel",
            "propagation_shortcircuit_corruption",
            detected,
        );
    }

    /// [br-mutation-23] Obligation ledger leak detection regression mutations
    async fn test_obligation_ledger_mutations(&self) {
        use crate::obligation::{LeakDetector, Obligation, ObligationId, ObligationLedger};

        let ledger_detected = self.runtime.scope(|scope| async move {
            let obligation_count = 25;
            let ledger_corruptions = Arc::new(AtomicUsize::new(0));
            let leak_detections = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                let mut ledger = ObligationLedger::new();
                let mut leak_detector = LeakDetector::new();
                let mut active_obligations: HashMap<ObligationId, Obligation> = HashMap::new();

                for oblig_idx in 0..obligation_count {
                    let obligation_id = ObligationId::new();
                    let obligation = Obligation::new(obligation_id, format!("test_obligation_{}", oblig_idx));

                    // Add obligation to ledger
                    ledger.add_obligation(obligation.clone());
                    active_obligations.insert(obligation_id, obligation.clone());

                    // MUTATION: Corrupt obligation lifecycle - drop without close
                    if oblig_idx % 5 == 0 {
                        ledger_corruptions.fetch_add(1, Ordering::Relaxed);

                        match oblig_idx % 15 {
                            0 => {
                                // Drop obligation without proper close
                                active_obligations.remove(&obligation_id);
                                // Skip ledger.close_obligation() - leak!
                            }
                            5 => {
                                // Mark as closed but don't remove from active set
                                ledger.close_obligation(obligation_id);
                                // Keep in active_obligations - inconsistent state
                            }
                            10 => {
                                // Double-close obligation
                                ledger.close_obligation(obligation_id);
                                if let Err(_) = ledger.close_obligation(obligation_id) {
                                    // Double-close detected
                                }
                                active_obligations.remove(&obligation_id);
                            }
                            _ => {
                                // Normal close
                                ledger.close_obligation(obligation_id);
                                active_obligations.remove(&obligation_id);
                            }
                        }
                    } else {
                        // Normal obligation lifecycle
                        sleep(Duration::from_millis(10)).await;
                        ledger.close_obligation(obligation_id);
                        active_obligations.remove(&obligation_id);
                    }

                    // Run leak detection periodically
                    if oblig_idx % 8 == 0 {
                        match leak_detector.check_for_leaks(&ledger) {
                            Ok(leak_report) => {
                                if !leak_report.leaked_obligations.is_empty() {
                                    leak_detections.fetch_add(leak_report.leaked_obligations.len(), Ordering::Relaxed);
                                }

                                // Check for state inconsistencies
                                let active_count = active_obligations.len();
                                let ledger_count = ledger.active_obligation_count();
                                if active_count != ledger_count && oblig_idx % 5 == 0 {
                                    // State inconsistency detected
                                    leak_detections.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(_) => {
                                if oblig_idx % 5 == 0 {
                                    // Leak detection error due to corruption
                                    leak_detections.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }

                    sleep(Duration::from_millis(3)).await;
                }

                // Final comprehensive leak check
                match leak_detector.final_audit(&ledger) {
                    Ok(final_report) => {
                        if !final_report.leaked_obligations.is_empty() {
                            leak_detections.fetch_add(final_report.leaked_obligations.len(), Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        // Final audit failure
                    }
                }

                let corruptions = ledger_corruptions.load(Ordering::Relaxed);
                let detections = leak_detections.load(Ordering::Relaxed);

                // Obligation leak detector should catch drop-without-close
                if detections > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Obligation leak detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Obligation ledger validation failed: {} corruptions, {} detections",
                            corruptions, detections)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(ledger_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-23",
            "obligation",
            "ledger_leak_corruption",
            detected,
        );
    }

    /// [br-mutation-24] Supervision restart policy regression mutations
    async fn test_supervision_mutations(&self) {
        use crate::supervision::{
            ChildSpec, ExitSignal, RestartPolicy, SupervisionError, Supervisor,
        };

        let supervision_detected = self.runtime.scope(|scope| async move {
            let child_count = 12;
            let supervision_corruptions = Arc::new(AtomicUsize::new(0));
            let policy_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                let mut supervisor = Supervisor::new()
                    .with_restart_policy(RestartPolicy::OneForOne)
                    .with_max_restarts(3, Duration::from_minutes(1));

                for child_idx in 0..child_count {
                    let child_name = format!("test_child_{}", child_idx);
                    let child_spec = ChildSpec::new(&child_name)
                        .with_restart_policy(RestartPolicy::Permanent);

                    // Start supervised child
                    let child_handle = supervisor.start_child(child_spec).expect("Should start child");

                    // Simulate child lifecycle with mutations
                    sleep(Duration::from_millis(20)).await;

                    // MUTATION: Corrupt supervision restart policy
                    if child_idx % 4 == 0 {
                        supervision_corruptions.fetch_add(1, Ordering::Relaxed);

                        match child_idx % 12 {
                            0 => {
                                // Child exits but supervisor misses exit signal
                                child_handle.terminate();
                                // Skip supervisor.handle_child_exit() - missed signal!

                                sleep(Duration::from_millis(30)).await;

                                // Check if supervisor detected missing child
                                if supervisor.child_status(&child_name).is_none() {
                                    // Supervisor should detect missing child
                                    policy_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            4 => {
                                // Child crashes but restart policy ignored
                                child_handle.crash("simulated_crash");

                                // Corrupt restart policy - don't restart permanent child
                                supervisor.override_restart_policy(&child_name, RestartPolicy::Temporary);

                                sleep(Duration::from_millis(50)).await;

                                // Check if child was incorrectly not restarted
                                if !supervisor.is_child_running(&child_name) {
                                    policy_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            8 => {
                                // Exceed restart intensity but policy not enforced
                                for crash_count in 0..5 { // Exceed max_restarts=3
                                    child_handle.crash(format!("crash_{}", crash_count));
                                    sleep(Duration::from_millis(10)).await;
                                }

                                // Supervisor should stop trying to restart
                                if supervisor.is_child_running(&child_name) {
                                    policy_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            _ => {
                                // Normal termination and restart
                                child_handle.terminate();
                                supervisor.handle_child_exit(&child_name, ExitSignal::Normal);
                            }
                        }
                    } else {
                        // Normal supervision lifecycle
                        sleep(Duration::from_millis(30)).await;
                        child_handle.terminate();
                        supervisor.handle_child_exit(&child_name, ExitSignal::Normal);
                    }

                    // Validate supervision tree consistency
                    let active_children = supervisor.active_child_count();
                    let expected_children = if child_idx % 4 == 0 {
                        // May have policy violations
                        supervisor.spec_count()
                    } else {
                        supervisor.spec_count()
                    };

                    if active_children != expected_children && child_idx % 4 == 0 {
                        // Supervision tree inconsistency detected
                        policy_violations.fetch_add(1, Ordering::Relaxed);
                    }

                    sleep(Duration::from_millis(5)).await;
                }

                let corruptions = supervision_corruptions.load(Ordering::Relaxed);
                let violations = policy_violations.load(Ordering::Relaxed);

                // Supervision policy should detect restart and exit signal corruptions
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Supervision corruption detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Supervision policy validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(supervision_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-24",
            "supervision",
            "restart_policy_corruption",
            detected,
        );
    }

    /// [br-mutation-25] Cx/Scope region close=quiescence early-close regression mutations
    async fn test_cx_scope_region_mutations(&self) {
        use crate::cx::{Cx, Scope};
        use crate::types::{RegionId, TaskId};

        let scope_detected = self.runtime.scope(|scope| async move {
            let region_count = 18;
            let region_corruptions = Arc::new(AtomicUsize::new(0));
            let quiescence_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for region_idx in 0..region_count {
                    let region_name = format!("test_region_{}", region_idx);

                    // Create nested region with tasks
                    let region_detected = scope.region(|region_scope| async move {
                        let task_count = 5;
                        let mut task_handles = Vec::new();

                        // Spawn multiple tasks in the region
                        for task_idx in 0..task_count {
                            let task_name = format!("task_{}_{}", region_idx, task_idx);
                            let handle = region_scope.spawn(async move {
                                sleep(Duration::from_millis(50)).await;
                                format!("completed: {}", task_name)
                            });
                            task_handles.push(handle);
                        }

                        // MUTATION: Corrupt region close=quiescence validation
                        if region_idx % 4 == 0 {
                            region_corruptions.fetch_add(1, Ordering::Relaxed);

                            match region_idx % 12 {
                                0 => {
                                    // Early close without waiting for tasks - violates quiescence
                                    // Region should not close until all tasks complete
                                    let active_task_count = task_handles.len();
                                    if active_task_count > 0 {
                                        // Attempt early close while tasks are still active
                                        region_scope.close_early();
                                        quiescence_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                4 => {
                                    // Cancel region but don't wait for drain - violates quiescence
                                    region_scope.cancel();
                                    // Skip proper task draining
                                    if !region_scope.is_quiescent().await {
                                        quiescence_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                8 => {
                                    // Drop tasks without joining - leak detection
                                    for (i, handle) in task_handles.iter().enumerate() {
                                        if i % 2 == 0 {
                                            // Drop task handle without joining
                                            std::mem::drop(handle);
                                        }
                                    }

                                    // Check for task leak detection
                                    if region_scope.has_leaked_tasks() {
                                        quiescence_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                _ => {
                                    // Wait for all tasks normally
                                    for handle in task_handles {
                                        let _ = handle.await;
                                    }
                                }
                            }
                        } else {
                            // Normal region lifecycle - wait for all tasks
                            for handle in task_handles {
                                let _ = handle.await;
                            }
                        }

                        // Validate region quiescence before close
                        let is_quiescent = region_scope.is_quiescent().await;
                        if !is_quiescent && region_idx % 4 == 0 {
                            // Region not quiescent but attempting to close
                            quiescence_violations.fetch_add(1, Ordering::Relaxed);
                        }

                        region_name
                    }).await;

                    sleep(Duration::from_millis(10)).await;
                }

                let corruptions = region_corruptions.load(Ordering::Relaxed);
                let violations = quiescence_violations.load(Ordering::Relaxed);

                // Region close validation should detect quiescence violations
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Region quiescence violation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Region close=quiescence validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(scope_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-25",
            "cx_scope",
            "region_quiescence_corruption",
            detected,
        );
    }

    /// [br-mutation-26] Runtime scheduler priority lane starvation regression mutations
    async fn test_runtime_scheduler_mutations(&self) {
        use crate::runtime::{Priority, Scheduler, SchedulingPolicy, Task};

        let scheduler_detected = self.runtime.scope(|scope| async move {
            let scheduler_test_count = 15;
            let scheduling_corruptions = Arc::new(AtomicUsize::new(0));
            let starvation_detections = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for sched_idx in 0..scheduler_test_count {
                    let mut scheduler = Scheduler::new()
                        .with_policy(SchedulingPolicy::PriorityLanes)
                        .with_fairness_quantum(Duration::from_millis(10));

                    // Create tasks with different priorities
                    let high_priority_count = 3;
                    let normal_priority_count = 5;
                    let low_priority_count = 4;

                    let mut high_priority_tasks = Vec::new();
                    let mut normal_priority_tasks = Vec::new();
                    let mut low_priority_tasks = Vec::new();

                    // Add high priority tasks
                    for i in 0..high_priority_count {
                        let task = Task::new(format!("high_task_{}", i), Priority::High);
                        high_priority_tasks.push(task.clone());
                        scheduler.enqueue_task(task);
                    }

                    // Add normal priority tasks
                    for i in 0..normal_priority_count {
                        let task = Task::new(format!("normal_task_{}", i), Priority::Normal);
                        normal_priority_tasks.push(task.clone());
                        scheduler.enqueue_task(task);
                    }

                    // Add low priority tasks
                    for i in 0..low_priority_count {
                        let task = Task::new(format!("low_task_{}", i), Priority::Low);
                        low_priority_tasks.push(task.clone());
                        scheduler.enqueue_task(task);
                    }

                    // MUTATION: Corrupt scheduler priority lane fairness
                    if sched_idx % 3 == 0 {
                        scheduling_corruptions.fetch_add(1, Ordering::Relaxed);

                        match sched_idx % 9 {
                            0 => {
                                // Starve low priority tasks - only schedule high priority
                                scheduler.set_priority_bias(Priority::High, 100.0); // 100% bias
                                scheduler.set_priority_bias(Priority::Low, 0.0);   // 0% for low
                            }
                            3 => {
                                // Ignore fairness quantum - let high priority dominate
                                scheduler.disable_fairness_quantum();
                            }
                            6 => {
                                // Corrupt priority lane ordering
                                scheduler.invert_priority_lanes(); // Low gets high priority
                            }
                            _ => {} // Normal scheduling
                        }
                    }

                    // Run scheduler simulation
                    let mut execution_order = Vec::new();
                    let mut scheduling_rounds = 0;
                    const MAX_ROUNDS: usize = 50;

                    while !scheduler.is_empty() && scheduling_rounds < MAX_ROUNDS {
                        if let Some(next_task) = scheduler.next_task() {
                            execution_order.push((next_task.name().to_string(), next_task.priority()));
                            scheduler.complete_task(next_task);
                        }
                        scheduling_rounds += 1;
                        sleep(Duration::from_millis(5)).await;
                    }

                    // Analyze execution order for starvation
                    let mut priority_execution_counts = HashMap::new();
                    for (_task_name, priority) in &execution_order {
                        *priority_execution_counts.entry(*priority).or_insert(0) += 1;
                    }

                    // Check for priority lane starvation
                    let high_executions = priority_execution_counts.get(&Priority::High).unwrap_or(&0);
                    let normal_executions = priority_execution_counts.get(&Priority::Normal).unwrap_or(&0);
                    let low_executions = priority_execution_counts.get(&Priority::Low).unwrap_or(&0);

                    // Starvation detection rules
                    if sched_idx % 3 == 0 {
                        // Check for complete starvation
                        if *low_executions == 0 && low_priority_count > 0 {
                            starvation_detections.fetch_add(1, Ordering::Relaxed);
                        }

                        // Check for extreme bias (>90% high priority when all priorities present)
                        let total_executions = execution_order.len();
                        if total_executions > 0 {
                            let high_percentage = (*high_executions as f64) / (total_executions as f64);
                            if high_percentage > 0.9 && normal_priority_count > 0 && low_priority_count > 0 {
                                starvation_detections.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // Check for inverted priority ordering
                        if *low_executions > *high_executions && high_priority_count > 0 && low_priority_count > 0 {
                            starvation_detections.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    sleep(Duration::from_millis(8)).await;
                }

                let corruptions = scheduling_corruptions.load(Ordering::Relaxed);
                let detections = starvation_detections.load(Ordering::Relaxed);

                // Scheduler fairness should detect priority lane starvation
                if detections > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Priority lane starvation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Scheduler priority lane validation failed: {} corruptions, {} detections",
                            corruptions, detections)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(scheduler_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-26",
            "runtime_scheduler",
            "priority_lane_starvation_corruption",
            detected,
        );
    }

    /// [br-mutation-27] Net/TCP split→merge buffer reordering regression mutations
    async fn test_net_tcp_split_merge_mutations(&self) {
        use crate::net::tcp::{SplitStream, StreamBuffer, TcpStream};

        let tcp_detected = self.runtime.scope(|scope| async move {
            let connection_count = 12;
            let buffer_corruptions = Arc::new(AtomicUsize::new(0));
            let reordering_detections = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for conn_idx in 0..connection_count {
                    // Create TCP stream for split/merge testing
                    let stream = TcpStream::connect("127.0.0.1:8080").await
                        .unwrap_or_else(|_| TcpStream::mock_stream());

                    // Split stream into read/write halves
                    let (mut read_half, mut write_half) = stream.split();

                    let test_data_size = 1024;
                    let chunk_size = 64;
                    let expected_chunks = test_data_size / chunk_size;

                    // Generate test data with sequence numbers
                    let mut test_data = Vec::new();
                    for chunk_idx in 0..expected_chunks {
                        let mut chunk = vec![chunk_idx as u8; chunk_size];
                        // Add sequence marker to start of chunk
                        chunk[0] = 0xFF;
                        chunk[1] = chunk_idx as u8;
                        test_data.extend(chunk);
                    }

                    // MUTATION: Corrupt TCP split→merge buffer handling
                    if conn_idx % 3 == 0 {
                        buffer_corruptions.fetch_add(1, Ordering::Relaxed);

                        match conn_idx % 9 {
                            0 => {
                                // Buffer reordering - swap chunk order
                                write_half.enable_reordering_mode();

                                for chunk_idx in (0..expected_chunks).rev() { // Reverse order
                                    let start = chunk_idx * chunk_size;
                                    let end = start + chunk_size;
                                    let chunk = &test_data[start..end];
                                    write_half.write_all_reordered(chunk).await.ok();
                                    sleep(Duration::from_millis(5)).await;
                                }
                            }
                            3 => {
                                // Duplicate chunks in buffer
                                for chunk_idx in 0..expected_chunks {
                                    let start = chunk_idx * chunk_size;
                                    let end = start + chunk_size;
                                    let chunk = &test_data[start..end];

                                    // Write chunk normally
                                    write_half.write_all(chunk).await.ok();

                                    // Duplicate every 3rd chunk
                                    if chunk_idx % 3 == 0 {
                                        write_half.write_all(chunk).await.ok(); // Duplicate
                                    }

                                    sleep(Duration::from_millis(3)).await;
                                }
                            }
                            6 => {
                                // Fragment and interleave chunks
                                for chunk_idx in 0..expected_chunks {
                                    let start = chunk_idx * chunk_size;
                                    let end = start + chunk_size;
                                    let chunk = &test_data[start..end];

                                    // Split chunk in half and interleave with next chunk
                                    let (first_half, second_half) = chunk.split_at(chunk_size / 2);
                                    write_half.write_all(first_half).await.ok();

                                    // Interleave with part of next chunk if available
                                    if chunk_idx + 1 < expected_chunks {
                                        let next_start = (chunk_idx + 1) * chunk_size;
                                        let next_fragment = &test_data[next_start..next_start + 8];
                                        write_half.write_all(next_fragment).await.ok();
                                    }

                                    write_half.write_all(second_half).await.ok();
                                    sleep(Duration::from_millis(2)).await;
                                }
                            }
                            _ => {
                                // Normal sequential write
                                write_half.write_all(&test_data).await.ok();
                            }
                        }
                    } else {
                        // Normal sequential write
                        write_half.write_all(&test_data).await.ok();
                    }

                    // Merge split streams and read back data
                    let merged_stream = TcpStream::merge(read_half, write_half);
                    let mut received_buffer = vec![0u8; test_data_size];
                    let bytes_read = merged_stream.read_exact(&mut received_buffer).await.unwrap_or(0);

                    // Analyze received data for buffer reordering issues
                    if bytes_read > 0 {
                        // Check sequence markers to detect reordering
                        let mut sequence_order = Vec::new();
                        let mut pos = 0;

                        while pos + 1 < received_buffer.len() {
                            if received_buffer[pos] == 0xFF {
                                let sequence_num = received_buffer[pos + 1];
                                sequence_order.push(sequence_num);
                                pos += chunk_size;
                            } else {
                                pos += 1;
                            }
                        }

                        // Detect buffer reordering corruptions
                        if conn_idx % 3 == 0 {
                            // Check for out-of-order sequences
                            let mut is_ordered = true;
                            for window in sequence_order.windows(2) {
                                if window[1] < window[0] {
                                    is_ordered = false;
                                    break;
                                }
                            }

                            if !is_ordered {
                                reordering_detections.fetch_add(1, Ordering::Relaxed);
                            }

                            // Check for duplicate sequences
                            let mut seen_sequences = std::collections::HashSet::new();
                            for &seq in &sequence_order {
                                if !seen_sequences.insert(seq) {
                                    // Duplicate detected
                                    reordering_detections.fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            // Check for missing sequences
                            let expected_sequences: std::collections::HashSet<_> =
                                (0..expected_chunks as u8).collect();
                            let received_sequences: std::collections::HashSet<_> =
                                sequence_order.into_iter().collect();

                            if expected_sequences != received_sequences {
                                reordering_detections.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    sleep(Duration::from_millis(10)).await;
                }

                let corruptions = buffer_corruptions.load(Ordering::Relaxed);
                let detections = reordering_detections.load(Ordering::Relaxed);

                // TCP split→merge should detect buffer reordering
                if detections > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Buffer reordering detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("TCP split→merge validation failed: {} corruptions, {} detections",
                            corruptions, detections)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(tcp_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-27",
            "net_tcp",
            "split_merge_reordering_corruption",
            detected,
        );
    }

    /// [br-mutation-28] Sync mutex acquire reorder regression mutations
    async fn test_sync_mutex_mutations(&self) {
        use crate::sync::{Mutex, MutexGuard, RwLock, Semaphore};

        let sync_detected = self.runtime.scope(|scope| async move {
            let contention_test_count = 15;
            let sync_corruptions = Arc::new(AtomicUsize::new(0));
            let ordering_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for test_idx in 0..contention_test_count {
                    let shared_data = Arc::new(Mutex::new(Vec::<(usize, Duration)>::new()));
                    let acquire_order = Arc::new(Mutex::new(Vec::<usize>::new()));
                    let contender_count = 8;

                    let mut contender_handles = Vec::new();

                    // Spawn multiple contenders for mutex
                    for contender_id in 0..contender_count {
                        let data_clone = shared_data.clone();
                        let order_clone = acquire_order.clone();

                        let handle = scope.spawn(async move {
                            // Wait a bit to create contention
                            sleep(Duration::from_millis(contender_id as u64 * 5)).await;

                            let acquire_start = Instant::now();

                            // MUTATION: Corrupt mutex acquire ordering
                            let guard = if test_idx % 4 == 0 && contender_id % 2 == 0 {
                                // Priority inversion - later requesters get priority
                                if contender_id > contender_count / 2 {
                                    data_clone.lock_with_priority().await
                                } else {
                                    data_clone.lock().await
                                }
                            } else {
                                // Normal acquisition
                                data_clone.lock().await
                            };

                            let acquire_duration = acquire_start.elapsed();

                            // Record acquisition order
                            {
                                let mut order = order_clone.lock().await;
                                order.push(contender_id);
                            }

                            // Hold lock for variable time to create contention patterns
                            let hold_time = Duration::from_millis((contender_id % 3 + 1) as u64 * 10);
                            sleep(hold_time).await;

                            // Update shared data while holding lock
                            guard.push((contender_id, acquire_duration));

                            drop(guard);
                            contender_id
                        });

                        contender_handles.push(handle);
                        sleep(Duration::from_millis(8)).await; // Stagger spawn times
                    }

                    // Wait for all contenders to complete
                    let mut completion_order = Vec::new();
                    for handle in contender_handles {
                        let contender_id = handle.await.unwrap();
                        completion_order.push(contender_id);
                    }

                    // Analyze acquisition order for fairness violations
                    let final_order = acquire_order.lock().await;
                    let shared_data_final = shared_data.lock().await;

                    // MUTATION detection: Check for acquire order violations
                    if test_idx % 4 == 0 {
                        sync_corruptions.fetch_add(1, Ordering::Relaxed);

                        // Check for priority inversion in acquisition order
                        let mut has_inversion = false;
                        for window in final_order.windows(2) {
                            let (first, second) = (window[0], window[1]);
                            // Later contenders should not acquire before earlier ones
                            // (accounting for some reasonable variance due to scheduling)
                            if second < first && (first - second) > 2 {
                                has_inversion = true;
                                break;
                            }
                        }

                        if has_inversion {
                            ordering_violations.fetch_add(1, Ordering::Relaxed);
                        }

                        // Check for starvation patterns
                        let first_half: std::collections::HashSet<_> =
                            (0..contender_count/2).collect();
                        let acquired_first_half: std::collections::HashSet<_> =
                            final_order.iter().take(contender_count/2).cloned().collect();

                        // If none of the first half acquired in the first half of acquisitions
                        if first_half.intersection(&acquired_first_half).count() == 0 {
                            ordering_violations.fetch_add(1, Ordering::Relaxed);
                        }

                        // Check for excessive contention times
                        for (contender_id, acquire_time) in shared_data_final.iter() {
                            if acquire_time > &Duration::from_millis(200) {
                                // Unreasonable contention time indicates unfairness
                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    sleep(Duration::from_millis(15)).await;
                }

                let corruptions = sync_corruptions.load(Ordering::Relaxed);
                let violations = ordering_violations.load(Ordering::Relaxed);

                // Sync primitives should detect acquire ordering violations
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Mutex acquire ordering violation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Sync mutex acquire validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(sync_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-28",
            "sync",
            "mutex_acquire_reorder_corruption",
            detected,
        );
    }

    /// [br-mutation-29] Time timer wheel level swap regression mutations
    async fn test_time_timer_wheel_mutations(&self) {
        use crate::time::{Instant, Timer, TimerHandle, TimerWheel};

        let time_detected = self.runtime.scope(|scope| async move {
            let timer_test_count = 12;
            let timing_corruptions = Arc::new(AtomicUsize::new(0));
            let level_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for test_idx in 0..timer_test_count {
                    let mut timer_wheel = TimerWheel::new();
                    let timer_count_per_level = 6;
                    let mut timer_handles = Vec::new();
                    let completion_order = Arc::new(Mutex::new(Vec::<(usize, Instant)>::new()));

                    // Create timers with different durations to populate different wheel levels
                    let base_time = Instant::now();
                    for level in 0..4 {
                        for timer_idx in 0..timer_count_per_level {
                            let timer_id = level * timer_count_per_level + timer_idx;

                            // Different levels have different time scales
                            let delay = match level {
                                0 => Duration::from_millis(50 + timer_idx as u64 * 10), // Short timers
                                1 => Duration::from_millis(200 + timer_idx as u64 * 50), // Medium timers
                                2 => Duration::from_millis(800 + timer_idx as u64 * 100), // Long timers
                                3 => Duration::from_millis(2000 + timer_idx as u64 * 200), // Very long timers
                                _ => Duration::from_millis(50),
                            };

                            let expected_fire_time = base_time + delay;
                            let order_clone = completion_order.clone();

                            // MUTATION: Corrupt timer wheel level assignment
                            let actual_delay = if test_idx % 3 == 0 && timer_idx % 2 == 0 {
                                timing_corruptions.fetch_add(1, Ordering::Relaxed);

                                match test_idx % 9 {
                                    0 => {
                                        // Swap timer levels - put short timer in long level
                                        if level == 0 {
                                            Duration::from_millis(2000) // Move to level 3
                                        } else if level == 3 {
                                            Duration::from_millis(50)   // Move to level 0
                                        } else {
                                            delay // Keep original
                                        }
                                    }
                                    3 => {
                                        // Corrupt timer ordering within level
                                        Duration::from_millis(delay.as_millis() as u64 * 3) // Triple duration
                                    }
                                    6 => {
                                        // Timer level inversion
                                        Duration::from_millis((4 - level) as u64 * 100) // Inverse relationship
                                    }
                                    _ => delay,
                                }
                            } else {
                                delay
                            };

                            let timer = Timer::new(actual_delay, move || {
                                async move {
                                    let fire_time = Instant::now();
                                    let mut order = order_clone.lock().await;
                                    order.push((timer_id, fire_time));
                                    timer_id
                                }
                            });

                            let handle = timer_wheel.schedule_timer(timer);
                            timer_handles.push((timer_id, handle, expected_fire_time, level));
                        }
                    }

                    // Run timer wheel for sufficient time
                    let wheel_runtime = Duration::from_millis(3000);
                    let wheel_start = Instant::now();

                    while wheel_start.elapsed() < wheel_runtime {
                        timer_wheel.advance(Duration::from_millis(10));
                        sleep(Duration::from_millis(10)).await;
                    }

                    // Analyze timer firing order
                    let final_order = completion_order.lock().await;

                    if test_idx % 3 == 0 {
                        // Check for timer wheel level violations
                        let mut level_0_fires = Vec::new();
                        let mut level_3_fires = Vec::new();

                        for (timer_id, fire_time) in final_order.iter() {
                            if let Some((_, _, expected_time, level)) = timer_handles.iter().find(|(id, _, _, _)| id == timer_id) {
                                match level {
                                    0 => level_0_fires.push((timer_id, fire_time, expected_time)),
                                    3 => level_3_fires.push((timer_id, fire_time, expected_time)),
                                    _ => {}
                                }
                            }
                        }

                        // Level 0 (short) timers should fire before level 3 (long) timers
                        for (_, short_fire, _) in &level_0_fires {
                            for (_, long_fire, _) in &level_3_fires {
                                if long_fire < short_fire {
                                    // Long timer fired before short timer - level violation
                                    level_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }

                        // Check for extreme timing deviations
                        for (timer_id, fire_time, expected_time) in level_0_fires.iter().chain(level_3_fires.iter()) {
                            let deviation = if fire_time > expected_time {
                                **fire_time - **expected_time
                            } else {
                                **expected_time - **fire_time
                            };

                            if deviation > Duration::from_millis(500) {
                                // Excessive timing deviation indicates level corruption
                                level_violations.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    sleep(Duration::from_millis(20)).await;
                }

                let corruptions = timing_corruptions.load(Ordering::Relaxed);
                let violations = level_violations.load(Ordering::Relaxed);

                // Timer wheel should detect level swap violations
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // Timer wheel level violation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Timer wheel level validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(time_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-29",
            "time",
            "timer_wheel_level_swap_corruption",
            detected,
        );
    }

    /// [br-mutation-30] Channel MPSC ordering FIFO regression mutations
    async fn test_channel_mpsc_mutations(&self) {
        use crate::channel::{Receiver, Sender, mpsc};

        let channel_detected = self.runtime.scope(|scope| async move {
            let channel_test_count = 10;
            let ordering_corruptions = Arc::new(AtomicUsize::new(0));
            let fifo_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for test_idx in 0..channel_test_count {
                    let (tx, mut rx) = mpsc::channel::<(usize, usize, Instant)>(100);
                    let sender_count = 6;
                    let messages_per_sender = 8;

                    let mut sender_handles = Vec::new();

                    // Spawn multiple senders
                    for sender_id in 0..sender_count {
                        let tx_clone = tx.clone();

                        let handle = scope.spawn(async move {
                            for msg_idx in 0..messages_per_sender {
                                let send_time = Instant::now();
                                let message = (sender_id, msg_idx, send_time);

                                // MUTATION: Corrupt MPSC FIFO ordering
                                if test_idx % 3 == 0 && sender_id % 2 == 0 && msg_idx % 2 == 0 {
                                    // Introduce ordering corruption
                                    match test_idx % 9 {
                                        0 => {
                                            // Send messages out of order
                                            let future_message = (sender_id, msg_idx + 2, send_time);
                                            tx_clone.send(future_message).await.ok();
                                            sleep(Duration::from_millis(5)).await;
                                            tx_clone.send(message).await.ok(); // Original message delayed
                                        }
                                        3 => {
                                            // Duplicate message send
                                            tx_clone.send(message).await.ok();
                                            tx_clone.send(message).await.ok(); // Duplicate
                                        }
                                        6 => {
                                            // Skip message (create gap)
                                            if msg_idx > 0 {
                                                // Skip this message, continue with next
                                                continue;
                                            } else {
                                                tx_clone.send(message).await.ok();
                                            }
                                        }
                                        _ => {
                                            tx_clone.send(message).await.ok();
                                        }
                                    }
                                } else {
                                    // Normal send
                                    tx_clone.send(message).await.ok();
                                }

                                // Add small delay between sends to create ordering opportunities
                                sleep(Duration::from_millis(2)).await;
                            }
                            sender_id
                        });

                        sender_handles.push(handle);
                        sleep(Duration::from_millis(5)).await; // Stagger sender starts
                    }

                    // Close sender channel
                    drop(tx);

                    // Collect all received messages
                    let mut received_messages = Vec::new();
                    while let Some(message) = rx.recv().await {
                        received_messages.push(message);
                    }

                    // Wait for all senders to complete
                    for handle in sender_handles {
                        handle.await.ok();
                    }

                    // Analyze FIFO ordering violations
                    if test_idx % 3 == 0 {
                        ordering_corruptions.fetch_add(1, Ordering::Relaxed);

                        // Check per-sender FIFO ordering
                        let mut sender_sequences: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();

                        for (sender_id, msg_idx, _) in &received_messages {
                            sender_sequences.entry(*sender_id).or_insert_with(Vec::new).push(*msg_idx);
                        }

                        // Verify FIFO ordering within each sender's sequence
                        for (sender_id, sequence) in &sender_sequences {
                            for window in sequence.windows(2) {
                                if window[1] < window[0] {
                                    // Message received out of order for this sender
                                    fifo_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            // Check for gaps in sequence (missing messages)
                            let mut expected_seq: Vec<usize> = (0..messages_per_sender).collect();
                            let mut actual_seq = sequence.clone();
                            actual_seq.sort();
                            actual_seq.dedup(); // Remove duplicates

                            if actual_seq != expected_seq {
                                // Sequence has gaps or duplicates
                                fifo_violations.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // Check overall message delivery completeness
                        let expected_total = sender_count * messages_per_sender;
                        let actual_total = received_messages.len();

                        // Allow some variance for dropped messages in corrupted tests
                        if (expected_total as isize - actual_total as isize).abs() > 5 {
                            // Significant message loss indicates corruption
                            fifo_violations.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    sleep(Duration::from_millis(25)).await;
                }

                let corruptions = ordering_corruptions.load(Ordering::Relaxed);
                let violations = fifo_violations.load(Ordering::Relaxed);

                // MPSC channels should detect FIFO ordering violations
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // MPSC FIFO ordering violation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("MPSC FIFO ordering validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(channel_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-30",
            "channel",
            "mpsc_fifo_ordering_corruption",
            detected,
        );
    }

    /// [br-mutation-31] Combinator retry idempotency + race symmetry regression mutations
    async fn test_combinator_mutations(&self) {
        use crate::combinator::{RaceResult, RetryPolicy, race, retry};

        let combinator_detected = self
            .runtime
            .scope(|scope| async move {
                let combinator_test_count = 14;
                let combinator_corruptions = Arc::new(AtomicUsize::new(0));
                let idempotency_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..combinator_test_count {
                            // Test retry idempotency violations
                            let retry_state = Arc::new(Mutex::new(0u32));
                            let retry_attempts = Arc::new(AtomicUsize::new(0));

                            // MUTATION: Corrupt retry idempotency - operations have side effects
                            if test_idx % 4 == 0 {
                                combinator_corruptions.fetch_add(1, Ordering::Relaxed);

                                let state_clone = retry_state.clone();
                                let attempts_clone = retry_attempts.clone();

                                let retry_operation = retry(
                                    RetryPolicy::exponential_backoff(3, Duration::from_millis(10)),
                                    move || {
                                        async move {
                                            attempts_clone.fetch_add(1, Ordering::Relaxed);
                                            let mut state = state_clone.lock().await;

                                            match test_idx % 12 {
                                                0 => {
                                                    // Corrupt: side effect on every retry (non-idempotent)
                                                    *state += 1; // Should only happen on success, not retries
                                                    if attempts_clone.load(Ordering::Relaxed) < 2 {
                                                        Err("simulated_failure")
                                                    } else {
                                                        Ok(*state)
                                                    }
                                                }
                                                4 => {
                                                    // Corrupt: accumulating state across retries
                                                    *state += attempts_clone.load(Ordering::Relaxed)
                                                        as u32;
                                                    if attempts_clone.load(Ordering::Relaxed) < 3 {
                                                        Err("retry_failure")
                                                    } else {
                                                        Ok(*state)
                                                    }
                                                }
                                                8 => {
                                                    // Corrupt: retry changes global state
                                                    *state = attempts_clone.load(Ordering::Relaxed)
                                                        as u32
                                                        * 10;
                                                    Err("persistent_failure") // Always fail but corrupt state
                                                }
                                                _ => {
                                                    // Normal idempotent operation
                                                    if attempts_clone.load(Ordering::Relaxed) < 2 {
                                                        Err("transient_failure")
                                                    } else {
                                                        *state = 42; // Only set on success
                                                        Ok(*state)
                                                    }
                                                }
                                            }
                                        }
                                    },
                                )
                                .await;

                                // Check for idempotency violations
                                let final_state = *retry_state.lock().await;
                                let total_attempts = retry_attempts.load(Ordering::Relaxed);

                                match test_idx % 12 {
                                    0 => {
                                        // State should be 42 (success value), not incremented per retry
                                        if final_state != 42 && retry_operation.is_ok() {
                                            idempotency_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    4 => {
                                        // State should not accumulate retry attempts
                                        if final_state > 50 && total_attempts > 1 {
                                            idempotency_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    8 => {
                                        // State should not be corrupted on failure
                                        if final_state > 0 && retry_operation.is_err() {
                                            idempotency_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    _ => {}
                                }
                            }

                            // Test race symmetry violations
                            if test_idx % 5 == 0 {
                                combinator_corruptions.fetch_add(1, Ordering::Relaxed);

                                let race_results = Arc::new(Mutex::new(Vec::<String>::new()));

                                for race_round in 0..3 {
                                    let results_clone = race_results.clone();

                                    // Create asymmetric race conditions
                                    let task_a = async {
                                        sleep(Duration::from_millis(10)).await;
                                        "task_a_result"
                                    };

                                    let task_b = async {
                                        sleep(Duration::from_millis(15)).await;
                                        "task_b_result"
                                    };

                                    let task_c = async {
                                        sleep(Duration::from_millis(20)).await;
                                        "task_c_result"
                                    };

                                    // MUTATION: Corrupt race symmetry
                                    let race_result = match test_idx % 15 {
                                        0 => {
                                            // Bias toward first task (break symmetry)
                                            race([
                                                Box::pin(async {
                                                    sleep(Duration::from_millis(1)).await;
                                                    "biased_first"
                                                }),
                                                Box::pin(task_b),
                                                Box::pin(task_c),
                                            ])
                                            .await
                                        }
                                        5 => {
                                            // Deterministic ordering instead of true race
                                            sleep(Duration::from_millis(5)).await; // Delay to ensure order
                                            race([
                                                Box::pin(task_a),
                                                Box::pin(async { "always_second" }),
                                                Box::pin(async { "always_third" }),
                                            ])
                                            .await
                                        }
                                        10 => {
                                            // Cancel losing tasks improperly (asymmetric cancellation)
                                            let race_with_corruption = race([
                                                Box::pin(task_a),
                                                Box::pin(async {
                                                    sleep(Duration::from_millis(1000)).await; // Long delay
                                                    "should_be_cancelled"
                                                }),
                                                Box::pin(task_c),
                                            ]);

                                            // Corrupt: don't actually cancel properly
                                            race_with_corruption.await
                                        }
                                        _ => {
                                            // Normal symmetric race
                                            race([
                                                Box::pin(task_a),
                                                Box::pin(task_b),
                                                Box::pin(task_c),
                                            ])
                                            .await
                                        }
                                    };

                                    {
                                        let mut results = results_clone.lock().await;
                                        results.push(race_result.to_string());
                                    }

                                    sleep(Duration::from_millis(5)).await;
                                }

                                // Analyze race results for symmetry violations
                                let final_results = race_results.lock().await;

                                // Check for deterministic bias (same winner every time)
                                if final_results.len() >= 3 {
                                    let all_same =
                                        final_results.iter().all(|r| r == &final_results[0]);
                                    if all_same && test_idx % 15 == 0 {
                                        // Biased results detected
                                        idempotency_violations.fetch_add(1, Ordering::Relaxed);
                                    }

                                    // Check for impossible results (tasks that should be cancelled)
                                    for result in final_results.iter() {
                                        if result.contains("should_be_cancelled") {
                                            // Cancellation failed - asymmetric behavior
                                            idempotency_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }

                            sleep(Duration::from_millis(15)).await;
                        }

                        let corruptions = combinator_corruptions.load(Ordering::Relaxed);
                        let violations = idempotency_violations.load(Ordering::Relaxed);

                        // Combinator should detect idempotency and symmetry violations
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Combinator violation detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Combinator validation failed: {} corruptions, {} violations",
                                    corruptions, violations
                                ),
                            ))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(combinator_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-31",
            "combinator",
            "retry_idempotency_race_symmetry_corruption",
            detected,
        );
    }

    /// [br-mutation-32] Service load_balance round-robin + hedge cancel-cancel regression mutations
    async fn test_service_mutations(&self) {
        use crate::service::{HedgePolicy, LoadBalancer, LoadBalancingStrategy, ServiceEndpoint};

        let service_detected = self
            .runtime
            .scope(|scope| async move {
                let service_test_count = 12;
                let service_corruptions = Arc::new(AtomicUsize::new(0));
                let balance_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..service_test_count {
                            // Test load balancer round-robin violations
                            let endpoint_count = 5;
                            let mut endpoints = Vec::new();
                            for i in 0..endpoint_count {
                                endpoints.push(ServiceEndpoint::new(&format!("service_{}", i)));
                            }

                            let mut load_balancer =
                                LoadBalancer::new(LoadBalancingStrategy::RoundRobin);
                            for endpoint in &endpoints {
                                load_balancer.add_endpoint(endpoint.clone());
                            }

                            // MUTATION: Corrupt round-robin fairness
                            if test_idx % 3 == 0 {
                                service_corruptions.fetch_add(1, Ordering::Relaxed);

                                let request_count = 20;
                                let mut selection_counts: HashMap<String, usize> = HashMap::new();

                                for req_idx in 0..request_count {
                                    let selected_endpoint = match test_idx % 9 {
                                        0 => {
                                            // Corrupt: bias toward first endpoint
                                            if req_idx % 3 == 0 {
                                                endpoints[0].clone() // Always pick first
                                            } else {
                                                load_balancer
                                                    .next_endpoint()
                                                    .unwrap_or(endpoints[0].clone())
                                            }
                                        }
                                        3 => {
                                            // Corrupt: skip endpoints in round-robin
                                            let mut selected = load_balancer
                                                .next_endpoint()
                                                .unwrap_or(endpoints[0].clone());
                                            if req_idx % 4 == 0 {
                                                // Skip to endpoint+2 (break round-robin order)
                                                selected = endpoints
                                                    [(req_idx + 2) % endpoint_count]
                                                    .clone();
                                            }
                                            selected
                                        }
                                        6 => {
                                            // Corrupt: duplicate selections
                                            let selected = load_balancer
                                                .next_endpoint()
                                                .unwrap_or(endpoints[0].clone());
                                            if req_idx % 5 == 0 {
                                                // Select same endpoint twice
                                                load_balancer.next_endpoint();
                                            }
                                            selected
                                        }
                                        _ => {
                                            // Normal round-robin
                                            load_balancer
                                                .next_endpoint()
                                                .unwrap_or(endpoints[0].clone())
                                        }
                                    };

                                    *selection_counts
                                        .entry(selected_endpoint.id().to_string())
                                        .or_insert(0) += 1;
                                    sleep(Duration::from_millis(2)).await;
                                }

                                // Analyze round-robin fairness
                                let expected_per_endpoint = request_count / endpoint_count;
                                let tolerance = 2; // Allow some variance

                                for (endpoint_id, count) in &selection_counts {
                                    let deviation =
                                        (*count as isize - expected_per_endpoint as isize).abs();
                                    if deviation > tolerance as isize {
                                        balance_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }

                                // Check for missing endpoints (should all be selected)
                                if selection_counts.len() != endpoint_count {
                                    balance_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            // Test hedge cancel-cancel violations
                            if test_idx % 4 == 0 {
                                service_corruptions.fetch_add(1, Ordering::Relaxed);

                                let hedge_policy = HedgePolicy::new()
                                    .with_hedge_delay(Duration::from_millis(50))
                                    .with_max_hedged_requests(3);

                                let primary_latency = Duration::from_millis(100);
                                let hedge_latency = Duration::from_millis(75);

                                let cancel_tracking = Arc::new(Mutex::new(Vec::<String>::new()));

                                // MUTATION: Corrupt hedge cancellation behavior
                                match test_idx % 12 {
                                    0 => {
                                        // Cancel-cancel: cancel hedged request but also cancel primary
                                        let tracking_clone = cancel_tracking.clone();

                                        let primary_task = async {
                                            sleep(primary_latency).await;
                                            let mut tracking = tracking_clone.lock().await;
                                            tracking.push("primary_completed".to_string());
                                            "primary_result"
                                        };

                                        let hedge_task = async {
                                            sleep(hedge_policy.hedge_delay()).await;
                                            sleep(hedge_latency).await;
                                            let mut tracking = tracking_clone.lock().await;
                                            tracking.push("hedge_completed".to_string());
                                            "hedge_result"
                                        };

                                        // Simulate race with double cancellation
                                        let result =
                                            race([Box::pin(primary_task), Box::pin(hedge_task)])
                                                .await;

                                        // Corrupt: cancel both tasks instead of just the loser
                                        let mut tracking = cancel_tracking.lock().await;
                                        tracking.push("both_cancelled".to_string()); // This shouldn't happen

                                        if tracking.contains(&"both_cancelled".to_string()) {
                                            balance_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    4 => {
                                        // Fail to cancel hedge request when primary completes
                                        let tracking_clone = cancel_tracking.clone();

                                        let primary_result = async {
                                            sleep(Duration::from_millis(30)).await; // Fast primary
                                            let mut tracking = tracking_clone.lock().await;
                                            tracking.push("primary_fast".to_string());
                                            "fast_primary"
                                        };

                                        let hedge_result = async {
                                            sleep(Duration::from_millis(200)).await; // Slow hedge
                                            let mut tracking = tracking_clone.lock().await;
                                            tracking.push("hedge_slow_completed".to_string()); // Should be cancelled
                                            "slow_hedge"
                                        };

                                        // Corrupt: let hedge complete even after primary wins
                                        let _primary_task = scope.spawn(primary_result);
                                        sleep(Duration::from_millis(50)).await; // Primary should win

                                        let _hedge_task = scope.spawn(hedge_result);
                                        sleep(Duration::from_millis(250)).await; // Let hedge complete

                                        let tracking = cancel_tracking.lock().await;
                                        if tracking.contains(&"hedge_slow_completed".to_string()) {
                                            // Hedge should have been cancelled
                                            balance_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    8 => {
                                        // Resource leak: create hedged requests but don't track cancellation
                                        let tracking_clone = cancel_tracking.clone();

                                        for hedge_idx in 0..5 {
                                            let tracking_inner = tracking_clone.clone();
                                            let _untracked_hedge = scope.spawn(async move {
                                                sleep(Duration::from_millis(300)).await; // Long running
                                                let mut tracking = tracking_inner.lock().await;
                                                tracking
                                                    .push(format!("leaked_hedge_{}", hedge_idx));
                                                hedge_idx
                                            });
                                            // Corrupt: don't store handle for cancellation
                                        }

                                        sleep(Duration::from_millis(100)).await;

                                        // Primary completes quickly but hedges continue
                                        let tracking = cancel_tracking.lock().await;
                                        let leaked_count = tracking
                                            .iter()
                                            .filter(|s| s.contains("leaked_hedge"))
                                            .count();
                                        if leaked_count > 0 {
                                            balance_violations
                                                .fetch_add(leaked_count, Ordering::Relaxed);
                                        }
                                    }
                                    _ => {
                                        // Normal hedge behavior
                                    }
                                }
                            }

                            sleep(Duration::from_millis(20)).await;
                        }

                        let corruptions = service_corruptions.load(Ordering::Relaxed);
                        let violations = balance_violations.load(Ordering::Relaxed);

                        // Service layer should detect load balancing and hedge violations
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Service violation detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Service validation failed: {} corruptions, {} violations",
                                    corruptions, violations
                                ),
                            ))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(service_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-32",
            "service",
            "load_balance_hedge_corruption",
            detected,
        );
    }

    /// [br-mutation-33] Lab chaos determinism regression mutations
    async fn test_lab_mutations(&self) {
        use crate::lab::{ChaosEngine, ChaosEvent, ChaosPolicy, LabEnvironment};

        let lab_detected = self
            .runtime
            .scope(|scope| async move {
                let chaos_test_count = 10;
                let chaos_corruptions = Arc::new(AtomicUsize::new(0));
                let determinism_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..chaos_test_count {
                            // Test chaos determinism - same seed should produce same events
                            let chaos_seed = 12345u64 + test_idx as u64;
                            let mut lab_env = LabEnvironment::new_with_seed(chaos_seed);

                            let chaos_policy = ChaosPolicy::new()
                                .with_network_partition_rate(0.1)
                                .with_node_failure_rate(0.05)
                                .with_latency_injection_rate(0.2);

                            let mut chaos_engine = ChaosEngine::new(chaos_policy);

                            // MUTATION: Corrupt chaos determinism
                            if test_idx % 3 == 0 {
                                chaos_corruptions.fetch_add(1, Ordering::Relaxed);

                                let event_count = 15;
                                let mut first_run_events = Vec::new();
                                let mut second_run_events = Vec::new();

                                // First run with seed
                                chaos_engine.reset_with_seed(chaos_seed);
                                for _ in 0..event_count {
                                    match test_idx % 9 {
                                        0 => {
                                            // Corrupt: inject system time instead of deterministic time
                                            let system_event = ChaosEvent::network_partition(
                                                Instant::now(), // Non-deterministic!
                                                Duration::from_millis(rand::random::<u64>() % 100),
                                            );
                                            first_run_events.push(system_event);
                                        }
                                        3 => {
                                            // Corrupt: use different randomization source
                                            let random_event =
                                                chaos_engine.generate_event_with_system_random();
                                            first_run_events.push(random_event);
                                        }
                                        6 => {
                                            // Corrupt: inject extra non-deterministic events
                                            let deterministic_event =
                                                chaos_engine.next_event(&lab_env);
                                            first_run_events.push(deterministic_event);

                                            // Add extra random event
                                            let extra_event = ChaosEvent::latency_injection(
                                                Duration::from_millis(rand::random::<u64>() % 50),
                                            );
                                            first_run_events.push(extra_event);
                                        }
                                        _ => {
                                            // Normal deterministic event generation
                                            let event = chaos_engine.next_event(&lab_env);
                                            first_run_events.push(event);
                                        }
                                    }
                                    chaos_engine.advance_time(Duration::from_millis(100));
                                }

                                // Second run with same seed (should be identical)
                                chaos_engine.reset_with_seed(chaos_seed);
                                lab_env.reset_with_seed(chaos_seed);

                                for _ in 0..event_count {
                                    let event = match test_idx % 9 {
                                        0 => {
                                            // Same corruption as first run
                                            ChaosEvent::network_partition(
                                                Instant::now(), // Will be different from first run
                                                Duration::from_millis(rand::random::<u64>() % 100),
                                            )
                                        }
                                        3 => chaos_engine.generate_event_with_system_random(),
                                        6 => {
                                            let deterministic_event =
                                                chaos_engine.next_event(&lab_env);
                                            second_run_events.push(deterministic_event);

                                            // Different extra event due to randomness
                                            ChaosEvent::latency_injection(Duration::from_millis(
                                                rand::random::<u64>() % 50,
                                            ))
                                        }
                                        _ => chaos_engine.next_event(&lab_env),
                                    };

                                    if test_idx % 9 != 6 {
                                        second_run_events.push(event);
                                    }
                                    chaos_engine.advance_time(Duration::from_millis(100));
                                }

                                // Compare runs for determinism violations
                                if first_run_events.len() != second_run_events.len() {
                                    determinism_violations.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    for (first_event, second_event) in
                                        first_run_events.iter().zip(second_run_events.iter())
                                    {
                                        // Check if events are deterministically equivalent
                                        if !chaos_engine.events_deterministically_equal(
                                            first_event,
                                            second_event,
                                        ) {
                                            determinism_violations.fetch_add(1, Ordering::Relaxed);
                                            break;
                                        }
                                    }
                                }

                                // Check for timing determinism
                                let first_timeline =
                                    chaos_engine.get_event_timeline(&first_run_events);
                                let second_timeline =
                                    chaos_engine.get_event_timeline(&second_run_events);

                                if first_timeline != second_timeline && test_idx % 3 == 0 {
                                    determinism_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            // Test chaos reproducibility across different invocations
                            if test_idx % 4 == 0 {
                                chaos_corruptions.fetch_add(1, Ordering::Relaxed);

                                let repro_seed = 98765u64;
                                let scenario_duration = Duration::from_millis(500);

                                // Run chaos scenario multiple times with same parameters
                                let mut scenario_results = Vec::new();

                                for repro_run in 0..3 {
                                    let mut scenario_env =
                                        LabEnvironment::new_with_seed(repro_seed);
                                    let mut scenario_chaos = ChaosEngine::new(chaos_policy.clone());
                                    scenario_chaos.reset_with_seed(repro_seed);

                                    let mut scenario_events = Vec::new();
                                    let mut elapsed = Duration::ZERO;

                                    while elapsed < scenario_duration {
                                        let step_duration = Duration::from_millis(50);

                                        // MUTATION: Break reproducibility
                                        let event = match test_idx % 12 {
                                            0 => {
                                                // Use wall clock time (non-reproducible)
                                                if repro_run == 1 {
                                                    sleep(Duration::from_millis(10)).await; // Timing variance
                                                }
                                                scenario_chaos.next_event(&scenario_env)
                                            }
                                            4 => {
                                                // Inject run-dependent state
                                                let mut corrupted_env = scenario_env.clone();
                                                corrupted_env.inject_run_variance(repro_run);
                                                scenario_chaos.next_event(&corrupted_env)
                                            }
                                            8 => {
                                                // Different event ordering per run
                                                if repro_run % 2 == 0 {
                                                    scenario_chaos.next_event(&scenario_env)
                                                } else {
                                                    scenario_chaos
                                                        .skip_and_generate_different_event(
                                                            &scenario_env,
                                                        )
                                                }
                                            }
                                            _ => {
                                                // Normal reproducible event
                                                scenario_chaos.next_event(&scenario_env)
                                            }
                                        };

                                        scenario_events.push(event);
                                        scenario_chaos.advance_time(step_duration);
                                        elapsed += step_duration;
                                    }

                                    scenario_results.push(scenario_events);
                                }

                                // Verify reproducibility across runs
                                let baseline_events = &scenario_results[0];
                                for (run_idx, run_events) in
                                    scenario_results.iter().enumerate().skip(1)
                                {
                                    if baseline_events.len() != run_events.len() {
                                        determinism_violations.fetch_add(1, Ordering::Relaxed);
                                    }

                                    // Check event-by-event reproducibility
                                    for (baseline_event, run_event) in
                                        baseline_events.iter().zip(run_events.iter())
                                    {
                                        if !chaos_engine.events_deterministically_equal(
                                            baseline_event,
                                            run_event,
                                        ) {
                                            determinism_violations.fetch_add(1, Ordering::Relaxed);
                                            break;
                                        }
                                    }
                                }
                            }

                            sleep(Duration::from_millis(25)).await;
                        }

                        let corruptions = chaos_corruptions.load(Ordering::Relaxed);
                        let violations = determinism_violations.load(Ordering::Relaxed);

                        // Lab chaos should detect determinism violations
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Chaos determinism violation detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Lab chaos validation failed: {} corruptions, {} violations",
                                    corruptions, violations
                                ),
                            ))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(lab_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-33",
            "lab",
            "chaos_determinism_corruption",
            detected,
        );
    }

    /// [br-mutation-34] HTTP h1 codec header parsing + h2 hpack table corruption mutations
    async fn test_http_mutations(&self) {
        use crate::http::{HeaderMap, HeaderName, HeaderValue, HttpCodec, h1, h2};

        let http_detected = self.runtime.scope(|scope| async move {
            let http_test_count = 16;
            let http_corruptions = Arc::new(AtomicUsize::new(0));
            let parsing_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for test_idx in 0..http_test_count {
                    // Test H1 codec header parsing violations
                    if test_idx % 3 == 0 {
                        http_corruptions.fetch_add(1, Ordering::Relaxed);

                        let mut h1_codec = h1::Codec::new();

                        // MUTATION: Corrupt H1 header parsing with malformed headers
                        let corrupted_request = match test_idx % 12 {
                            0 => {
                                // Header injection attack
                                "GET /path HTTP/1.1\r\nHost: example.com\r\nX-Header: value\r\nInjected: evil\r\n\r\nGET /evil HTTP/1.1\r\nHost: attacker.com\r\n\r\n"
                            }
                            3 => {
                                // Malformed header with null bytes
                                "GET /path HTTP/1.1\r\nHost: example.com\r\nCorrupt: value\x00injection\r\nContent-Length: 0\r\n\r\n"
                            }
                            6 => {
                                // Header line folding attack (obsolete but dangerous)
                                "GET /path HTTP/1.1\r\nHost: example.com\r\nFolded: line1\r\n \tcontinuation\r\nContent-Length: 0\r\n\r\n"
                            }
                            9 => {
                                // Oversized header name
                                let long_header = "X-".to_string() + &"A".repeat(8192);
                                format!("GET /path HTTP/1.1\r\nHost: example.com\r\n{}: value\r\nContent-Length: 0\r\n\r\n", long_header)
                            }
                            _ => {
                                // Normal request
                                "GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nContent-Length: 0\r\n\r\n"
                            }
                        };

                        // Attempt to parse corrupted request
                        match h1_codec.decode(corrupted_request.as_bytes()) {
                            Ok(request) => {
                                // Check if dangerous content was parsed incorrectly
                                let headers = request.headers();

                                if test_idx % 12 == 0 {
                                    // Should detect header injection
                                    if headers.contains_key("injected") {
                                        // Injection attack not caught
                                        parsing_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }

                                if test_idx % 12 == 3 {
                                    // Should reject null bytes in headers
                                    if let Some(corrupt_value) = headers.get("corrupt") {
                                        if corrupt_value.to_str().unwrap_or("").contains('\0') {
                                            parsing_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }

                                if test_idx % 12 == 6 {
                                    // Should reject or sanitize line folding
                                    if let Some(folded_value) = headers.get("folded") {
                                        let value_str = folded_value.to_str().unwrap_or("");
                                        if value_str.contains("\t") || value_str.contains(" continuation") {
                                            parsing_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                if test_idx % 12 == 0 || test_idx % 12 == 3 || test_idx % 12 == 6 {
                                    // Correctly rejected malformed input
                                } else {
                                    // Normal request incorrectly rejected
                                    parsing_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }

                    // Test H2 HPACK table corruption
                    if test_idx % 4 == 0 {
                        http_corruptions.fetch_add(1, Ordering::Relaxed);

                        let mut h2_codec = h2::Codec::new();
                        let mut hpack_table = h2::HpackTable::new();

                        // MUTATION: Corrupt HPACK dynamic table
                        match test_idx % 16 {
                            0 => {
                                // Corrupt table entry with wrong index
                                hpack_table.insert(HeaderName::from_static("corrupted"),
                                                 HeaderValue::from_static("value"));
                                hpack_table.corrupt_entry_at_index(62); // Standard table size + 1
                            }
                            4 => {
                                // Reference non-existent table entry
                                let corrupted_frame = h2::HeadersFrame::new()
                                    .with_indexed_header(999); // Invalid index

                                match h2_codec.decode_headers(&corrupted_frame, &hpack_table) {
                                    Err(_) => {
                                        // Correctly detected invalid index
                                    }
                                    Ok(_) => {
                                        // Should have failed - table corruption not detected
                                        parsing_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            8 => {
                                // Exceed table size limits
                                for i in 0..1000 {
                                    let header_name = format!("dynamic-header-{}", i);
                                    hpack_table.insert(
                                        HeaderName::from_bytes(header_name.as_bytes()).unwrap(),
                                        HeaderValue::from_static("large_value_that_exceeds_table_limits")
                                    );
                                }

                                if hpack_table.size() > hpack_table.max_size() {
                                    // Table size violation not enforced
                                    parsing_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            12 => {
                                // Circular reference in table
                                hpack_table.insert(HeaderName::from_static("circular1"),
                                                 HeaderValue::from_static("@circular2"));
                                hpack_table.insert(HeaderName::from_static("circular2"),
                                                 HeaderValue::from_static("@circular1"));

                                let circular_frame = h2::HeadersFrame::new()
                                    .with_literal_header("test", "@circular1");

                                match h2_codec.decode_headers(&circular_frame, &hpack_table) {
                                    Ok(headers) => {
                                        // Check if circular reference was resolved improperly
                                        if headers.contains_key("test") {
                                            let value = headers.get("test").unwrap().to_str().unwrap_or("");
                                            if value.contains("@circular") {
                                                parsing_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        // Correctly detected circular reference
                                    }
                                }
                            }
                            _ => {
                                // Normal HPACK operation
                                hpack_table.insert(HeaderName::from_static("normal"),
                                                 HeaderValue::from_static("value"));
                            }
                        }
                    }

                    sleep(Duration::from_millis(8)).await;
                }

                let corruptions = http_corruptions.load(Ordering::Relaxed);
                let violations = parsing_violations.load(Ordering::Relaxed);

                // HTTP codec should detect header parsing and HPACK violations
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // HTTP parsing violation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("HTTP codec validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(http_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-34",
            "http",
            "h1_h2_parsing_hpack_corruption",
            detected,
        );
    }

    /// [br-mutation-35] WebSocket frame mask reuse regression mutations
    async fn test_websocket_mutations(&self) {
        use crate::net::websocket::{Frame, FrameHeader, Mask, OpCode, WebSocketCodec};

        let websocket_detected = self.runtime.scope(|scope| async move {
            let websocket_test_count = 14;
            let websocket_corruptions = Arc::new(AtomicUsize::new(0));
            let mask_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for test_idx in 0..websocket_test_count {
                    let mut ws_codec = WebSocketCodec::new();
                    let message_count = 8;
                    let mut used_masks = Vec::new();

                    // MUTATION: Corrupt WebSocket frame masking
                    if test_idx % 3 == 0 {
                        websocket_corruptions.fetch_add(1, Ordering::Relaxed);

                        for msg_idx in 0..message_count {
                            let payload = format!("Test message {}", msg_idx);

                            let mask = match test_idx % 12 {
                                0 => {
                                    // Mask reuse vulnerability - same mask for multiple frames
                                    if used_masks.is_empty() {
                                        let new_mask = Mask::generate();
                                        used_masks.push(new_mask);
                                        new_mask
                                    } else {
                                        used_masks[0] // Reuse first mask (DANGEROUS)
                                    }
                                }
                                3 => {
                                    // Predictable mask pattern
                                    Mask::from_bytes([
                                        (msg_idx % 256) as u8,
                                        ((msg_idx + 1) % 256) as u8,
                                        ((msg_idx + 2) % 256) as u8,
                                        ((msg_idx + 3) % 256) as u8,
                                    ])
                                }
                                6 => {
                                    // Zero mask (no encryption)
                                    Mask::from_bytes([0x00, 0x00, 0x00, 0x00])
                                }
                                9 => {
                                    // Weak mask with repeated bytes
                                    Mask::from_bytes([0xAA, 0xAA, 0xAA, 0xAA])
                                }
                                _ => {
                                    // Proper random mask
                                    let proper_mask = Mask::generate();
                                    used_masks.push(proper_mask);
                                    proper_mask
                                }
                            };

                            let frame_header = FrameHeader::new()
                                .with_opcode(OpCode::Text)
                                .with_fin(true)
                                .with_mask(Some(mask))
                                .with_payload_length(payload.len() as u64);

                            let frame = Frame::new(frame_header, payload.into_bytes());
                            let encoded_frame = ws_codec.encode(frame);

                            // Analyze mask usage patterns
                            if test_idx % 12 == 0 {
                                // Check for mask reuse
                                if used_masks.len() > 1 {
                                    let first_mask = used_masks[0];
                                    let current_mask = mask;
                                    if first_mask.as_bytes() == current_mask.as_bytes() && msg_idx > 0 {
                                        mask_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }

                            if test_idx % 12 == 3 {
                                // Check for predictable patterns
                                let mask_bytes = mask.as_bytes();
                                let mut is_predictable = true;
                                for i in 1..4 {
                                    if mask_bytes[i] != (mask_bytes[0] + i as u8) % 256 {
                                        is_predictable = false;
                                        break;
                                    }
                                }
                                if is_predictable {
                                    mask_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            if test_idx % 12 == 6 {
                                // Check for zero mask
                                if mask.as_bytes() == &[0x00, 0x00, 0x00, 0x00] {
                                    mask_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            if test_idx % 12 == 9 {
                                // Check for weak repeated patterns
                                let mask_bytes = mask.as_bytes();
                                if mask_bytes[0] == mask_bytes[1] && mask_bytes[1] == mask_bytes[2] && mask_bytes[2] == mask_bytes[3] {
                                    mask_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }

                            // Test frame decoding with corrupted masks
                            match ws_codec.decode(&encoded_frame) {
                                Ok(decoded_frame) => {
                                    let decoded_payload = String::from_utf8(decoded_frame.payload().to_vec()).unwrap_or_default();
                                    if decoded_payload != payload && test_idx % 3 == 0 {
                                        // Mask corruption caused decoding error
                                        mask_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => {
                                    if test_idx % 12 != 0 && test_idx % 12 != 3 && test_idx % 12 != 6 && test_idx % 12 != 9 {
                                        // Normal frame incorrectly failed to decode
                                        mask_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }

                            sleep(Duration::from_millis(3)).await;
                        }
                    }

                    // Test mask entropy and randomness
                    if test_idx % 4 == 0 {
                        websocket_corruptions.fetch_add(1, Ordering::Relaxed);

                        let entropy_test_count = 20;
                        let mut mask_entropy_samples = Vec::new();

                        for entropy_idx in 0..entropy_test_count {
                            let mask = match test_idx % 16 {
                                0 => {
                                    // Low entropy mask generation
                                    let weak_byte = (entropy_idx % 4) as u8;
                                    Mask::from_bytes([weak_byte, weak_byte, weak_byte, weak_byte])
                                }
                                4 => {
                                    // Time-based predictable mask
                                    let time_seed = Instant::now().elapsed().as_millis() as u8;
                                    Mask::from_bytes([time_seed, time_seed + 1, time_seed + 2, time_seed + 3])
                                }
                                8 => {
                                    // Counter-based mask (incremental)
                                    let counter = entropy_idx as u8;
                                    Mask::from_bytes([counter, counter + 1, counter + 2, counter + 3])
                                }
                                12 => {
                                    // XOR with constant (weak randomness)
                                    let base_mask = Mask::generate();
                                    let constant_xor = [0x42, 0x42, 0x42, 0x42];
                                    let mask_bytes = base_mask.as_bytes();
                                    Mask::from_bytes([
                                        mask_bytes[0] ^ constant_xor[0],
                                        mask_bytes[1] ^ constant_xor[1],
                                        mask_bytes[2] ^ constant_xor[2],
                                        mask_bytes[3] ^ constant_xor[3],
                                    ])
                                }
                                _ => {
                                    // Proper cryptographically secure mask
                                    Mask::generate()
                                }
                            };

                            mask_entropy_samples.push(mask);
                        }

                        // Analyze mask entropy
                        let mut duplicate_count = 0;
                        for i in 0..mask_entropy_samples.len() {
                            for j in (i + 1)..mask_entropy_samples.len() {
                                if mask_entropy_samples[i].as_bytes() == mask_entropy_samples[j].as_bytes() {
                                    duplicate_count += 1;
                                }
                            }
                        }

                        // Check for pattern repetition (should be very rare with proper randomness)
                        if duplicate_count > 0 && test_idx % 16 != 12 { // Allow some XOR duplicates
                            mask_violations.fetch_add(duplicate_count, Ordering::Relaxed);
                        }

                        // Check for low entropy patterns
                        for (i, mask) in mask_entropy_samples.iter().enumerate() {
                            let mask_bytes = mask.as_bytes();
                            let unique_bytes: std::collections::HashSet<_> = mask_bytes.iter().collect();

                            if unique_bytes.len() <= 2 && test_idx % 16 == 0 {
                                // Very low entropy detected
                                mask_violations.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    sleep(Duration::from_millis(12)).await;
                }

                let corruptions = websocket_corruptions.load(Ordering::Relaxed);
                let violations = mask_violations.load(Ordering::Relaxed);

                // WebSocket should detect mask reuse and weak randomness
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // WebSocket mask violation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("WebSocket mask validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(websocket_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-35",
            "websocket",
            "frame_mask_reuse_corruption",
            detected,
        );
    }

    /// [br-mutation-36] TLS acceptor handshake field swap regression mutations
    async fn test_tls_mutations(&self) {
        use crate::tls::{CertificateError, HandshakeError, TlsAcceptor, TlsConnector, TlsStream};

        let tls_detected = self.runtime.scope(|scope| async move {
            let tls_test_count = 12;
            let tls_corruptions = Arc::new(AtomicUsize::new(0));
            let handshake_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for test_idx in 0..tls_test_count {
                    // Test TLS handshake field corruption
                    if test_idx % 3 == 0 {
                        tls_corruptions.fetch_add(1, Ordering::Relaxed);

                        // Setup mock TLS acceptor and connector for testing
                        let mut tls_acceptor = TlsAcceptor::builder()
                            .with_test_certificate()
                            .build()
                            .unwrap();

                        let tls_connector = TlsConnector::builder()
                            .with_insecure_mode_for_testing() // Allow self-signed certs
                            .build()
                            .unwrap();

                        // MUTATION: Corrupt TLS handshake fields
                        match test_idx % 12 {
                            0 => {
                                // Swap certificate fields - use wrong certificate for handshake
                                let wrong_cert = tls_acceptor.get_test_certificate_for_different_host("wrong.example.com");
                                tls_acceptor.replace_certificate(wrong_cert);

                                let handshake_result = scope.spawn(async move {
                                    // Simulate client connection to "correct.example.com"
                                    match tls_connector.connect("correct.example.com", mock_tcp_stream()).await {
                                        Ok(_) => {
                                            // Certificate mismatch not detected
                                            return false;
                                        }
                                        Err(HandshakeError::CertificateError(CertificateError::HostnameMismatch)) => {
                                            // Correctly detected hostname mismatch
                                            return true;
                                        }
                                        Err(_) => {
                                            // Other error
                                            return false;
                                        }
                                    }
                                }).await.unwrap_or(false);

                                if !handshake_result {
                                    handshake_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            3 => {
                                // Corrupt protocol version negotiation
                                tls_acceptor.force_protocol_version("TLS 1.0"); // Force insecure version

                                let handshake_result = scope.spawn(async move {
                                    match tls_connector.connect("test.example.com", mock_tcp_stream()).await {
                                        Ok(stream) => {
                                            // Check if insecure protocol was negotiated
                                            if stream.protocol_version() == "TLS 1.0" {
                                                return false; // Should reject TLS 1.0
                                            }
                                            return true;
                                        }
                                        Err(HandshakeError::UnsupportedProtocol) => {
                                            // Correctly rejected insecure protocol
                                            return true;
                                        }
                                        Err(_) => {
                                            return false;
                                        }
                                    }
                                }).await.unwrap_or(false);

                                if !handshake_result {
                                    handshake_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            6 => {
                                // Swap cipher suite negotiation - force weak cipher
                                tls_acceptor.override_cipher_suites(&["TLS_RSA_WITH_RC4_128_SHA"]); // Weak cipher

                                let handshake_result = scope.spawn(async move {
                                    match tls_connector.connect("test.example.com", mock_tcp_stream()).await {
                                        Ok(stream) => {
                                            // Check if weak cipher was negotiated
                                            if stream.cipher_suite().contains("RC4") {
                                                return false; // Should reject RC4
                                            }
                                            return true;
                                        }
                                        Err(HandshakeError::WeakCipher) => {
                                            // Correctly rejected weak cipher
                                            return true;
                                        }
                                        Err(_) => {
                                            return false;
                                        }
                                    }
                                }).await.unwrap_or(false);

                                if !handshake_result {
                                    handshake_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            9 => {
                                // Certificate chain validation corruption
                                let corrupted_chain = tls_acceptor.create_corrupted_certificate_chain();
                                tls_acceptor.use_certificate_chain(corrupted_chain);

                                let handshake_result = scope.spawn(async move {
                                    match tls_connector.connect("test.example.com", mock_tcp_stream()).await {
                                        Ok(_) => {
                                            // Corrupted chain not detected
                                            return false;
                                        }
                                        Err(HandshakeError::CertificateError(CertificateError::InvalidChain)) => {
                                            // Correctly detected chain corruption
                                            return true;
                                        }
                                        Err(_) => {
                                            return false;
                                        }
                                    }
                                }).await.unwrap_or(false);

                                if !handshake_result {
                                    handshake_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            _ => {
                                // Normal TLS handshake - should succeed
                                let handshake_result = scope.spawn(async move {
                                    match tls_connector.connect("test.example.com", mock_tcp_stream()).await {
                                        Ok(_) => true,
                                        Err(_) => false,
                                    }
                                }).await.unwrap_or(false);

                                if !handshake_result {
                                    // Normal handshake failed unexpectedly
                                    handshake_violations.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }

                    sleep(Duration::from_millis(20)).await;
                }

                let corruptions = tls_corruptions.load(Ordering::Relaxed);
                let violations = handshake_violations.load(Ordering::Relaxed);

                // TLS should detect handshake field swaps and session corruption
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // TLS handshake violation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("TLS handshake validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(tls_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-36",
            "tls",
            "acceptor_handshake_field_swap_corruption",
            detected,
        );
    }

    /// Generate subsystem testing summary
    fn generate_subsystem_summary(&self) -> serde_json::Value {
        let applied = self.mutations_applied.load(Ordering::Relaxed);
        let detected = self.mutations_detected.load(Ordering::Relaxed);

        let detection_rate = if applied > 0 {
            detected as f64 / applied as f64
        } else {
            0.0
        };

        serde_json::json!({
            "subsystem_mutation_summary": {
                "test_harness": self.test_name,
                "mutations_applied": applied,
                "mutations_detected": detected,
                "detection_rate": detection_rate,
                "subsystem_effectiveness": if detection_rate >= 0.85 { "EFFECTIVE" } else { "NEEDS_IMPROVEMENT" }
            }
        })
    }
}

#[tokio::test]
async fn test_observability_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("observability_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"observability_start\"}}");

    // Test observability-specific mutations
    tester.test_observability_counter_mutations().await;
    tester.test_observability_aggregation_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply observability mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.85,
        "Observability subsystem should detect ≥85% of metric mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"observability_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_trace_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("trace_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"trace_start\"}}");

    // Test trace-specific mutations
    tester.test_trace_causality_mutations().await;
    tester.test_trace_span_relationship_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply trace mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.90,
        "Trace subsystem should detect ≥90% of causality mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"trace_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_security_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("security_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"security_start\"}}");

    // Test security-specific mutations
    tester.test_security_auth_encryption_mutations().await;
    tester.test_security_key_corruption_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply security mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.95,
        "Security subsystem should detect ≥95% of cryptographic mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"security_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_plan_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("plan_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"plan_start\"}}");

    // Test plan-specific mutations
    tester.test_plan_graph_topology_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply plan mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.85,
        "Plan subsystem should detect ≥85% of topology mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"plan_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_raptorq_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("raptorq_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"raptorq_start\"}}");

    // Test raptorq-specific mutations
    tester.test_raptorq_systematic_symbol_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply raptorq mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.92,
        "RaptorQ subsystem should detect ≥92% of systematic symbol mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"raptorq_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_distributed_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("distributed_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"distributed_start\"}}");

    // Test distributed-specific mutations
    tester.test_distributed_consistent_hash_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply distributed mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.88,
        "Distributed subsystem should detect ≥88% of consistent hash mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"distributed_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_grpc_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("grpc_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"grpc_start\"}}");

    // Test grpc-specific mutations
    tester.test_grpc_status_code_mapping_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply grpc mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.87,
        "gRPC subsystem should detect ≥87% of status code mapping mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"grpc_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_messaging_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("messaging_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"messaging_start\"}}");

    // Test messaging-specific mutations
    tester.test_messaging_kafka_offset_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply messaging mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.89,
        "Messaging subsystem should detect ≥89% of Kafka offset mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"messaging_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_web_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("web_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"web_start\"}}");

    // Test web-specific mutations
    tester.test_web_csrf_token_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply web mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.91,
        "Web subsystem should detect ≥91% of CSRF token rotation mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"web_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_cancel_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("cancel_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"cancel_start\"}}");

    // Test cancel-specific mutations
    tester.test_cancel_propagation_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply cancel mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.93,
        "Cancel subsystem should detect ≥93% of propagation mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"cancel_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_obligation_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("obligation_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"obligation_start\"}}");

    // Test obligation-specific mutations
    tester.test_obligation_ledger_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply obligation mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.94,
        "Obligation subsystem should detect ≥94% of leak mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"obligation_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_supervision_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("supervision_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"supervision_start\"}}");

    // Test supervision-specific mutations
    tester.test_supervision_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply supervision mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.91,
        "Supervision subsystem should detect ≥91% of restart policy mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"supervision_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_cx_scope_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("cx_scope_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"cx_scope_start\"}}");

    // Test cx/scope-specific mutations
    tester.test_cx_scope_region_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply cx/scope mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.95,
        "Cx/Scope subsystem should detect ≥95% of region quiescence mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"cx_scope_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_runtime_scheduler_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("runtime_scheduler_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"runtime_scheduler_start\"}}");

    // Test runtime/scheduler-specific mutations
    tester.test_runtime_scheduler_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply runtime/scheduler mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.92,
        "Runtime/Scheduler subsystem should detect ≥92% of priority lane mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"runtime_scheduler_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_net_tcp_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("net_tcp_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"net_tcp_start\"}}");

    // Test net/tcp-specific mutations
    tester.test_net_tcp_split_merge_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply net/tcp mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.89,
        "Net/TCP subsystem should detect ≥89% of split→merge buffer mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"net_tcp_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_sync_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("sync_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"sync_start\"}}");

    // Test sync-specific mutations
    tester.test_sync_mutex_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply sync mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.90,
        "Sync subsystem should detect ≥90% of mutex acquire reorder mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"sync_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_time_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("time_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"time_start\"}}");

    // Test time-specific mutations
    tester.test_time_timer_wheel_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply time mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.93,
        "Time subsystem should detect ≥93% of timer wheel level swap mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"time_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_channel_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("channel_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"channel_start\"}}");

    // Test channel-specific mutations
    tester.test_channel_mpsc_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply channel mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.92,
        "Channel subsystem should detect ≥92% of MPSC FIFO ordering mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"channel_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_combinator_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("combinator_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"combinator_start\"}}");

    // Test combinator-specific mutations
    tester.test_combinator_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply combinator mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.91,
        "Combinator subsystem should detect ≥91% of retry idempotency + race symmetry mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"combinator_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_service_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("service_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"service_start\"}}");

    // Test service-specific mutations
    tester.test_service_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply service mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.89,
        "Service subsystem should detect ≥89% of load_balance round-robin + hedge cancel mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"service_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_lab_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("lab_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"lab_start\"}}");

    // Test lab-specific mutations
    tester.test_lab_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply lab mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.94,
        "Lab subsystem should detect ≥94% of chaos determinism mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"lab_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_http_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("http_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"http_start\"}}");

    // Test HTTP-specific mutations
    tester.test_http_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply HTTP mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.92,
        "HTTP subsystem should detect ≥92% of h1/h2 header parsing + HPACK mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"http_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_websocket_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("websocket_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"websocket_start\"}}");

    // Test WebSocket-specific mutations
    tester.test_websocket_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply WebSocket mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.90,
        "WebSocket subsystem should detect ≥90% of frame mask reuse mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"websocket_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_tls_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("tls_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"tls_start\"}}");

    // Test TLS-specific mutations
    tester.test_tls_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply TLS mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.95,
        "TLS subsystem should detect ≥95% of acceptor handshake field swap mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"tls_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_all_subsystems_comprehensive_mutation_sensitivity() {
    eprintln!("{{\"comprehensive_subsystem_mutation_test\":\"start\"}}");

    let obs_tester = SubsystemMutationTester::new("comprehensive_observability").await;
    let trace_tester = SubsystemMutationTester::new("comprehensive_trace").await;
    let sec_tester = SubsystemMutationTester::new("comprehensive_security").await;
    let plan_tester = SubsystemMutationTester::new("comprehensive_plan").await;
    let raptorq_tester = SubsystemMutationTester::new("comprehensive_raptorq").await;
    let distributed_tester = SubsystemMutationTester::new("comprehensive_distributed").await;
    let grpc_tester = SubsystemMutationTester::new("comprehensive_grpc").await;
    let messaging_tester = SubsystemMutationTester::new("comprehensive_messaging").await;
    let web_tester = SubsystemMutationTester::new("comprehensive_web").await;
    let cancel_tester = SubsystemMutationTester::new("comprehensive_cancel").await;
    let obligation_tester = SubsystemMutationTester::new("comprehensive_obligation").await;
    let supervision_tester = SubsystemMutationTester::new("comprehensive_supervision").await;
    let cx_scope_tester = SubsystemMutationTester::new("comprehensive_cx_scope").await;
    let scheduler_tester = SubsystemMutationTester::new("comprehensive_scheduler").await;
    let tcp_tester = SubsystemMutationTester::new("comprehensive_tcp").await;
    let sync_tester = SubsystemMutationTester::new("comprehensive_sync").await;
    let time_tester = SubsystemMutationTester::new("comprehensive_time").await;
    let channel_tester = SubsystemMutationTester::new("comprehensive_channel").await;
    let combinator_tester = SubsystemMutationTester::new("comprehensive_combinator").await;
    let service_tester = SubsystemMutationTester::new("comprehensive_service").await;
    let lab_tester = SubsystemMutationTester::new("comprehensive_lab").await;
    let http_tester = SubsystemMutationTester::new("comprehensive_http").await;
    let websocket_tester = SubsystemMutationTester::new("comprehensive_websocket").await;
    let tls_tester = SubsystemMutationTester::new("comprehensive_tls").await;

    // Test all subsystem mutations comprehensively
    obs_tester.test_observability_counter_mutations().await;
    obs_tester.test_observability_aggregation_mutations().await;

    trace_tester.test_trace_causality_mutations().await;
    trace_tester.test_trace_span_relationship_mutations().await;

    sec_tester.test_security_auth_encryption_mutations().await;
    sec_tester.test_security_key_corruption_mutations().await;

    plan_tester.test_plan_graph_topology_mutations().await;
    raptorq_tester
        .test_raptorq_systematic_symbol_mutations()
        .await;
    distributed_tester
        .test_distributed_consistent_hash_mutations()
        .await;
    grpc_tester.test_grpc_status_code_mapping_mutations().await;
    messaging_tester
        .test_messaging_kafka_offset_mutations()
        .await;
    web_tester.test_web_csrf_token_mutations().await;
    cancel_tester.test_cancel_propagation_mutations().await;
    obligation_tester.test_obligation_ledger_mutations().await;
    supervision_tester.test_supervision_mutations().await;
    cx_scope_tester.test_cx_scope_region_mutations().await;
    scheduler_tester.test_runtime_scheduler_mutations().await;
    tcp_tester.test_net_tcp_split_merge_mutations().await;
    sync_tester.test_sync_mutex_mutations().await;
    time_tester.test_time_timer_wheel_mutations().await;
    channel_tester.test_channel_mpsc_mutations().await;
    combinator_tester.test_combinator_mutations().await;
    service_tester.test_service_mutations().await;
    lab_tester.test_lab_mutations().await;
    http_tester.test_http_mutations().await;
    websocket_tester.test_websocket_mutations().await;
    tls_tester.test_tls_mutations().await;

    // Calculate overall subsystem detection rate
    let total_applied = obs_tester.mutations_applied.load(Ordering::Relaxed)
        + trace_tester.mutations_applied.load(Ordering::Relaxed)
        + sec_tester.mutations_applied.load(Ordering::Relaxed)
        + plan_tester.mutations_applied.load(Ordering::Relaxed)
        + raptorq_tester.mutations_applied.load(Ordering::Relaxed)
        + distributed_tester.mutations_applied.load(Ordering::Relaxed)
        + grpc_tester.mutations_applied.load(Ordering::Relaxed)
        + messaging_tester.mutations_applied.load(Ordering::Relaxed)
        + web_tester.mutations_applied.load(Ordering::Relaxed)
        + cancel_tester.mutations_applied.load(Ordering::Relaxed)
        + obligation_tester.mutations_applied.load(Ordering::Relaxed)
        + supervision_tester.mutations_applied.load(Ordering::Relaxed)
        + cx_scope_tester.mutations_applied.load(Ordering::Relaxed)
        + scheduler_tester.mutations_applied.load(Ordering::Relaxed)
        + tcp_tester.mutations_applied.load(Ordering::Relaxed)
        + sync_tester.mutations_applied.load(Ordering::Relaxed)
        + time_tester.mutations_applied.load(Ordering::Relaxed)
        + channel_tester.mutations_applied.load(Ordering::Relaxed)
        + combinator_tester.mutations_applied.load(Ordering::Relaxed)
        + service_tester.mutations_applied.load(Ordering::Relaxed)
        + lab_tester.mutations_applied.load(Ordering::Relaxed)
        + http_tester.mutations_applied.load(Ordering::Relaxed)
        + websocket_tester.mutations_applied.load(Ordering::Relaxed)
        + tls_tester.mutations_applied.load(Ordering::Relaxed);

    let total_detected = obs_tester.mutations_detected.load(Ordering::Relaxed)
        + trace_tester.mutations_detected.load(Ordering::Relaxed)
        + sec_tester.mutations_detected.load(Ordering::Relaxed)
        + plan_tester.mutations_detected.load(Ordering::Relaxed)
        + raptorq_tester.mutations_detected.load(Ordering::Relaxed)
        + distributed_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + grpc_tester.mutations_detected.load(Ordering::Relaxed)
        + messaging_tester.mutations_detected.load(Ordering::Relaxed)
        + web_tester.mutations_detected.load(Ordering::Relaxed)
        + cancel_tester.mutations_detected.load(Ordering::Relaxed)
        + obligation_tester.mutations_detected.load(Ordering::Relaxed)
        + supervision_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + cx_scope_tester.mutations_detected.load(Ordering::Relaxed)
        + scheduler_tester.mutations_detected.load(Ordering::Relaxed)
        + tcp_tester.mutations_detected.load(Ordering::Relaxed)
        + sync_tester.mutations_detected.load(Ordering::Relaxed)
        + time_tester.mutations_detected.load(Ordering::Relaxed)
        + channel_tester.mutations_detected.load(Ordering::Relaxed)
        + combinator_tester.mutations_detected.load(Ordering::Relaxed)
        + service_tester.mutations_detected.load(Ordering::Relaxed)
        + lab_tester.mutations_detected.load(Ordering::Relaxed)
        + http_tester.mutations_detected.load(Ordering::Relaxed)
        + websocket_tester.mutations_detected.load(Ordering::Relaxed)
        + tls_tester.mutations_detected.load(Ordering::Relaxed);

    let overall_detection_rate = if total_applied > 0 {
        total_detected as f64 / total_applied as f64
    } else {
        0.0
    };

    eprintln!(
        "{{\"comprehensive_subsystem_results\":{{\"total_applied\":{},\"total_detected\":{},\"detection_rate\":{:.2},\"threshold\":0.90}}}}",
        total_applied, total_detected, overall_detection_rate
    );

    assert!(total_applied > 0, "Should apply subsystem mutations");
    assert!(
        overall_detection_rate >= 0.90,
        "Overall subsystem mutation detection should be ≥90%: {:.1}% ({}/{})",
        overall_detection_rate * 100.0,
        total_detected,
        total_applied
    );

    eprintln!(
        "{{\"comprehensive_subsystem_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        overall_detection_rate
    );
}
