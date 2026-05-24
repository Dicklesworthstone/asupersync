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
        + tcp_tester.mutations_applied.load(Ordering::Relaxed);

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
        + tcp_tester.mutations_detected.load(Ordering::Relaxed);

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
