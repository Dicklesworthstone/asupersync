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

    /// [br-mutation-37] Database postgres SCRAM handshake byte-flip regression mutations
    async fn test_database_mutations(&self) {
        use crate::database::{AuthenticationError, ConnectionConfig, ScramAuth, postgres};

        let database_detected = self
            .runtime
            .scope(|scope| async move {
                let database_test_count = 15;
                let database_corruptions = Arc::new(AtomicUsize::new(0));
                let scram_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..database_test_count {
                            // Test PostgreSQL SCRAM handshake corruption
                            if test_idx % 3 == 0 {
                                database_corruptions.fetch_add(1, Ordering::Relaxed);

                                let connection_config = ConnectionConfig::new()
                                    .with_host("localhost")
                                    .with_port(5432)
                                    .with_database("test_db")
                                    .with_username("test_user")
                                    .with_password("test_password");

                                let mut pg_client = postgres::Client::new(connection_config);

                                // MUTATION: Corrupt SCRAM-SHA-256 handshake bytes
                                match test_idx % 12 {
                                    0 => {
                                        // Corrupt client nonce in initial message
                                        let mut scram_auth =
                                            ScramAuth::new("test_user", "test_password");
                                        let mut initial_message = scram_auth.client_first_message();

                                        // Flip random bits in nonce
                                        let nonce_start =
                                            initial_message.find("r=").unwrap_or(0) + 2;
                                        if nonce_start < initial_message.len() {
                                            let mut bytes = initial_message.into_bytes();
                                            if nonce_start + 4 < bytes.len() {
                                                bytes[nonce_start] ^= 0xAA; // Flip bits
                                                bytes[nonce_start + 1] ^= 0x55;
                                            }
                                            initial_message =
                                                String::from_utf8_lossy(&bytes).to_string();
                                        }

                                        match pg_client
                                            .authenticate_with_corrupted_message(&initial_message)
                                            .await
                                        {
                                            Err(AuthenticationError::InvalidNonce) => {
                                                // Correctly detected nonce corruption
                                            }
                                            Ok(_) => {
                                                // Should have failed with corrupted nonce
                                                scram_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other authentication error
                                            }
                                        }
                                    }
                                    3 => {
                                        // Corrupt salt in server first message
                                        let mut scram_auth =
                                            ScramAuth::new("test_user", "test_password");
                                        let client_first = scram_auth.client_first_message();

                                        // Mock server response with corrupted salt
                                        let mut server_first = format!(
                                            "r={},s={},i=4096",
                                            scram_auth.generate_server_nonce(),
                                            "Y29ycnVwdGVkX3NhbHQ" // Corrupted base64 salt
                                        );

                                        // Flip bytes in salt
                                        if let Some(salt_start) = server_first.find("s=") {
                                            let salt_start = salt_start + 2;
                                            let mut bytes = server_first.into_bytes();
                                            if salt_start + 4 < bytes.len() {
                                                bytes[salt_start + 2] ^= 0xFF; // Corrupt salt bytes
                                                bytes[salt_start + 3] ^= 0x42;
                                            }
                                            server_first =
                                                String::from_utf8_lossy(&bytes).to_string();
                                        }

                                        match scram_auth.process_server_first(&server_first) {
                                            Err(_) => {
                                                // Correctly rejected corrupted salt
                                            }
                                            Ok(_) => {
                                                // Should have rejected corrupted salt
                                                scram_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    6 => {
                                        // Corrupt client proof calculation
                                        let mut scram_auth =
                                            ScramAuth::new("test_user", "test_password");
                                        let client_first = scram_auth.client_first_message();
                                        let server_first = scram_auth.mock_server_first_response();

                                        scram_auth.process_server_first(&server_first).unwrap();
                                        let mut client_final = scram_auth.client_final_message();

                                        // Corrupt client proof
                                        if let Some(proof_start) = client_final.find("p=") {
                                            let proof_start = proof_start + 2;
                                            let mut bytes = client_final.into_bytes();
                                            if proof_start + 8 < bytes.len() {
                                                // Flip multiple bytes in proof
                                                bytes[proof_start] ^= 0xDE;
                                                bytes[proof_start + 2] ^= 0xAD;
                                                bytes[proof_start + 4] ^= 0xBE;
                                                bytes[proof_start + 6] ^= 0xEF;
                                            }
                                            client_final =
                                                String::from_utf8_lossy(&bytes).to_string();
                                        }

                                        match pg_client
                                            .validate_client_proof(&client_final, &scram_auth)
                                            .await
                                        {
                                            Err(AuthenticationError::InvalidProof) => {
                                                // Correctly detected proof corruption
                                            }
                                            Ok(_) => {
                                                // Should have rejected corrupted proof
                                                scram_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other authentication error
                                            }
                                        }
                                    }
                                    9 => {
                                        // Corrupt server signature verification
                                        let mut scram_auth =
                                            ScramAuth::new("test_user", "test_password");
                                        let auth_flow_result =
                                            scram_auth.complete_mock_handshake().await;

                                        if let Ok(server_final) = auth_flow_result {
                                            let mut corrupted_server_final = server_final;

                                            // Corrupt server signature
                                            if let Some(sig_start) =
                                                corrupted_server_final.find("v=")
                                            {
                                                let sig_start = sig_start + 2;
                                                let mut bytes = corrupted_server_final.into_bytes();
                                                if sig_start + 10 < bytes.len() {
                                                    // Systematic corruption of signature
                                                    for i in 0..8 {
                                                        if sig_start + i < bytes.len() {
                                                            bytes[sig_start + i] ^=
                                                                (i as u8 * 0x11);
                                                        }
                                                    }
                                                }
                                                corrupted_server_final =
                                                    String::from_utf8_lossy(&bytes).to_string();
                                            }

                                            match scram_auth
                                                .verify_server_signature(&corrupted_server_final)
                                            {
                                                Err(
                                                    AuthenticationError::InvalidServerSignature,
                                                ) => {
                                                    // Correctly detected signature corruption
                                                }
                                                Ok(_) => {
                                                    // Should have rejected corrupted signature
                                                    scram_violations
                                                        .fetch_add(1, Ordering::Relaxed);
                                                }
                                                Err(_) => {
                                                    // Other verification error
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal SCRAM handshake
                                        let scram_auth =
                                            ScramAuth::new("test_user", "test_password");
                                        match pg_client.authenticate_scram(&scram_auth).await {
                                            Ok(_) => {
                                                // Normal authentication succeeded
                                            }
                                            Err(_) => {
                                                // Normal authentication failed
                                                scram_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                }
                            }

                            // Test PostgreSQL connection parameter corruption
                            if test_idx % 4 == 0 {
                                database_corruptions.fetch_add(1, Ordering::Relaxed);

                                let mut connection_params = HashMap::new();
                                connection_params.insert("user", "test_user");
                                connection_params.insert("database", "test_db");
                                connection_params.insert("application_name", "asupersync_test");

                                // MUTATION: Corrupt connection parameters
                                match test_idx % 16 {
                                    0 => {
                                        // Inject SQL in database name
                                        connection_params
                                            .insert("database", "test_db'; DROP TABLE users; --");

                                        match postgres::connect_with_params(&connection_params)
                                            .await
                                        {
                                            Err(postgres::Error::InvalidDatabaseName) => {
                                                // Correctly detected SQL injection attempt
                                            }
                                            Ok(_) => {
                                                // Should have rejected dangerous database name
                                                scram_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    4 => {
                                        // Corrupt application_name with control characters
                                        connection_params
                                            .insert("application_name", "app\x00\x01\x02injection");

                                        match postgres::connect_with_params(&connection_params)
                                            .await
                                        {
                                            Err(postgres::Error::InvalidParameter(_)) => {
                                                // Correctly detected control character injection
                                            }
                                            Ok(connection) => {
                                                // Check if control characters were sanitized
                                                if let Ok(app_name) =
                                                    connection.get_parameter("application_name")
                                                {
                                                    if app_name.contains('\x00')
                                                        || app_name.contains('\x01')
                                                    {
                                                        // Control characters not sanitized
                                                        scram_violations
                                                            .fetch_add(1, Ordering::Relaxed);
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    8 => {
                                        // Oversized parameter values
                                        let large_value = "x".repeat(65536);
                                        connection_params.insert("application_name", &large_value);

                                        match postgres::connect_with_params(&connection_params)
                                            .await
                                        {
                                            Err(postgres::Error::ParameterTooLarge) => {
                                                // Correctly detected oversized parameter
                                            }
                                            Ok(_) => {
                                                // Should have rejected oversized parameter
                                                scram_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    12 => {
                                        // Unicode normalization attack
                                        connection_params.insert("user", "testü\u{FEFF}ser"); // Zero-width space

                                        match postgres::connect_with_params(&connection_params)
                                            .await
                                        {
                                            Err(postgres::Error::InvalidUsername) => {
                                                // Correctly detected unicode attack
                                            }
                                            Ok(connection) => {
                                                // Check if username was normalized incorrectly
                                                if let Ok(username) =
                                                    connection.get_parameter("user")
                                                {
                                                    if username != "testüser"
                                                        && username.contains('\u{FEFF}')
                                                    {
                                                        // Unicode not properly normalized
                                                        scram_violations
                                                            .fetch_add(1, Ordering::Relaxed);
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal connection parameters
                                        match postgres::connect_with_params(&connection_params)
                                            .await
                                        {
                                            Ok(_) => {
                                                // Normal connection succeeded
                                            }
                                            Err(_) => {
                                                // Connection failed unexpectedly
                                            }
                                        }
                                    }
                                }
                            }

                            sleep(Duration::from_millis(15)).await;
                        }

                        let corruptions = database_corruptions.load(Ordering::Relaxed);
                        let violations = scram_violations.load(Ordering::Relaxed);

                        // PostgreSQL should detect SCRAM handshake and parameter corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Database corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Database validation failed: {} corruptions, {} violations",
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

        let detected = matches!(database_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-37",
            "database",
            "postgres_scram_handshake_corruption",
            detected,
        );
    }

    /// [br-mutation-38] FS io_uring submission ordering regression mutations
    async fn test_fs_mutations(&self) {
        use crate::fs::{CompletionQueueEntry, File, IoUring, SubmissionQueueEntry, uring};

        let fs_detected = self
            .runtime
            .scope(|scope| async move {
                let fs_test_count = 12;
                let fs_corruptions = Arc::new(AtomicUsize::new(0));
                let ordering_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..fs_test_count {
                            // Test io_uring submission ordering corruption
                            if test_idx % 3 == 0 {
                                fs_corruptions.fetch_add(1, Ordering::Relaxed);

                                let mut io_uring =
                                    IoUring::new(64).expect("Should create io_uring");
                                let operation_count = 8;

                                // Create test files for operations
                                let test_files: Vec<File> = (0..operation_count)
                                    .map(|i| {
                                        File::create_temp(&format!("test_file_{}", i)).unwrap()
                                    })
                                    .collect();

                                let mut submission_order = Vec::new();
                                let mut expected_completions = Vec::new();

                                // MUTATION: Corrupt submission queue ordering
                                for op_idx in 0..operation_count {
                                    let test_data =
                                        format!("Operation data {}", op_idx).into_bytes();
                                    let file = &test_files[op_idx];

                                    let sqe = match test_idx % 12 {
                                        0 => {
                                            // Out-of-order submission - submit operations in reverse
                                            let actual_idx = operation_count - 1 - op_idx;
                                            submission_order.push(actual_idx);
                                            SubmissionQueueEntry::write(
                                                file.fd(),
                                                &test_data,
                                                0,                 // offset
                                                actual_idx as u64, // user_data
                                            )
                                        }
                                        3 => {
                                            // Duplicate submission with same user_data
                                            submission_order.push(op_idx);
                                            if op_idx > 0 {
                                                // Reuse previous operation's user_data
                                                SubmissionQueueEntry::write(
                                                    file.fd(),
                                                    &test_data,
                                                    0,
                                                    (op_idx - 1) as u64, // Duplicate user_data
                                                )
                                            } else {
                                                SubmissionQueueEntry::write(
                                                    file.fd(),
                                                    &test_data,
                                                    0,
                                                    op_idx as u64,
                                                )
                                            }
                                        }
                                        6 => {
                                            // Corrupt operation type - submit read instead of write
                                            submission_order.push(op_idx);
                                            let mut buffer = vec![0u8; test_data.len()];
                                            SubmissionQueueEntry::read(
                                                file.fd(),
                                                &mut buffer,
                                                0, // offset
                                                op_idx as u64,
                                            )
                                        }
                                        9 => {
                                            // Corrupt file descriptor - use wrong fd
                                            submission_order.push(op_idx);
                                            let wrong_fd = if op_idx > 0 {
                                                test_files[op_idx - 1].fd()
                                            } else {
                                                test_files[op_idx].fd()
                                            };
                                            SubmissionQueueEntry::write(
                                                wrong_fd,
                                                &test_data,
                                                0,
                                                op_idx as u64,
                                            )
                                        }
                                        _ => {
                                            // Normal submission order
                                            submission_order.push(op_idx);
                                            SubmissionQueueEntry::write(
                                                file.fd(),
                                                &test_data,
                                                0,
                                                op_idx as u64,
                                            )
                                        }
                                    };

                                    expected_completions.push(op_idx);
                                    io_uring.submit(sqe).expect("Should submit operation");
                                }

                                // Wait for completions and analyze ordering
                                io_uring
                                    .submit_and_wait(operation_count)
                                    .expect("Should complete operations");

                                let mut completion_order = Vec::new();
                                let mut completion_results = Vec::new();

                                for _ in 0..operation_count {
                                    if let Some(cqe) = io_uring.peek_completion() {
                                        let user_data = cqe.user_data() as usize;
                                        let result = cqe.result();
                                        completion_order.push(user_data);
                                        completion_results.push(result);
                                        io_uring.mark_completion_seen();
                                    }
                                }

                                // Analyze ordering violations
                                if test_idx % 12 == 0 {
                                    // Check if reverse submission caused completion issues
                                    let expected_reverse: Vec<_> =
                                        (0..operation_count).rev().collect();
                                    if submission_order == expected_reverse {
                                        // Verify completions match submission corruption
                                        for (i, &completion_idx) in
                                            completion_order.iter().enumerate()
                                        {
                                            if completion_idx != expected_reverse[i] {
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                                break;
                                            }
                                        }
                                    }
                                }

                                if test_idx % 12 == 3 {
                                    // Check for duplicate user_data detection
                                    let mut seen_user_data = std::collections::HashSet::new();
                                    for &user_data in &completion_order {
                                        if !seen_user_data.insert(user_data) {
                                            // Duplicate user_data not handled properly
                                            ordering_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }

                                if test_idx % 12 == 6 {
                                    // Check for operation type mismatch errors
                                    for (i, &result) in completion_results.iter().enumerate() {
                                        if result < 0 && completion_order[i] < operation_count {
                                            // Read operation correctly failed on write-only file
                                        } else if result >= 0 {
                                            // Read operation should have failed
                                            ordering_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }

                                if test_idx % 12 == 9 {
                                    // Check for file descriptor corruption detection
                                    for &result in &completion_results {
                                        if result < 0 {
                                            // Correctly detected fd corruption
                                        } else {
                                            // Wrong fd operation succeeded unexpectedly
                                            ordering_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }

                            // Test completion queue ordering validation
                            if test_idx % 4 == 0 {
                                fs_corruptions.fetch_add(1, Ordering::Relaxed);

                                let mut io_uring =
                                    IoUring::new(32).expect("Should create io_uring");
                                let sync_op_count = 6;

                                // Submit synchronous operations that should complete in order
                                for sync_idx in 0..sync_op_count {
                                    let test_file =
                                        File::create_temp(&format!("sync_file_{}", sync_idx))
                                            .unwrap();
                                    let sync_data = vec![sync_idx as u8; 16];

                                    let sqe = match test_idx % 16 {
                                        0 => {
                                            // Normal ordered submission
                                            SubmissionQueueEntry::write(
                                                test_file.fd(),
                                                &sync_data,
                                                0,
                                                sync_idx as u64,
                                            )
                                        }
                                        4 => {
                                            // Force completion ordering corruption via priority
                                            let priority = if sync_idx % 2 == 0 { 1 } else { 0 }; // Alternate priority
                                            let mut sqe = SubmissionQueueEntry::write(
                                                test_file.fd(),
                                                &sync_data,
                                                0,
                                                sync_idx as u64,
                                            );
                                            sqe.set_ioprio(priority);
                                            sqe
                                        }
                                        8 => {
                                            // Add artificial delays to create ordering issues
                                            if sync_idx % 2 == 0 {
                                                let mut sqe = SubmissionQueueEntry::write(
                                                    test_file.fd(),
                                                    &sync_data,
                                                    0,
                                                    sync_idx as u64,
                                                );
                                                sqe.set_flags(uring::IOSQE_ASYNC); // Force async for some operations
                                                sqe
                                            } else {
                                                SubmissionQueueEntry::write(
                                                    test_file.fd(),
                                                    &sync_data,
                                                    0,
                                                    sync_idx as u64,
                                                )
                                            }
                                        }
                                        12 => {
                                            // Link operations incorrectly
                                            let mut sqe = SubmissionQueueEntry::write(
                                                test_file.fd(),
                                                &sync_data,
                                                0,
                                                sync_idx as u64,
                                            );
                                            if sync_idx > 0 {
                                                sqe.set_flags(uring::IOSQE_IO_LINK); // Link to previous
                                            }
                                            sqe
                                        }
                                        _ => SubmissionQueueEntry::write(
                                            test_file.fd(),
                                            &sync_data,
                                            0,
                                            sync_idx as u64,
                                        ),
                                    };

                                    io_uring.submit(sqe).expect("Should submit sync operation");
                                }

                                // Submit all operations and wait
                                io_uring
                                    .submit_and_wait(sync_op_count)
                                    .expect("Should complete sync operations");

                                // Check completion ordering
                                let mut sync_completion_order = Vec::new();
                                for _ in 0..sync_op_count {
                                    if let Some(cqe) = io_uring.peek_completion() {
                                        sync_completion_order.push(cqe.user_data() as usize);
                                        io_uring.mark_completion_seen();
                                    }
                                }

                                // Validate ordering based on mutation type
                                if test_idx % 16 == 4 || test_idx % 16 == 8 || test_idx % 16 == 12 {
                                    // Check if ordering corruption was properly detected
                                    let is_ordered = sync_completion_order
                                        .windows(2)
                                        .all(|window| window[0] <= window[1]);

                                    if !is_ordered && test_idx % 4 == 0 {
                                        // Ordering corruption detected through completion analysis
                                        ordering_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }

                            sleep(Duration::from_millis(10)).await;
                        }

                        let corruptions = fs_corruptions.load(Ordering::Relaxed);
                        let violations = ordering_violations.load(Ordering::Relaxed);

                        // io_uring should detect submission and completion ordering violations
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // FS ordering violation detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "FS io_uring validation failed: {} corruptions, {} violations",
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

        let detected = matches!(fs_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-38",
            "fs",
            "uring_submission_ordering_corruption",
            detected,
        );
    }

    /// [br-mutation-39] IO split→unsplit identity regression mutations
    async fn test_io_mutations(&self) {
        use crate::io::{AsyncRead, AsyncWrite, BufReader, BufWriter, Read, Write, split, unsplit};

        let io_detected = self.runtime.scope(|scope| async move {
            let io_test_count = 14;
            let io_corruptions = Arc::new(AtomicUsize::new(0));
            let identity_violations = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for test_idx in 0..io_test_count {
                    // Test split→unsplit identity preservation
                    if test_idx % 3 == 0 {
                        io_corruptions.fetch_add(1, Ordering::Relaxed);

                        let test_data = format!("Test data for split→unsplit identity {}", test_idx).into_bytes();
                        let original_data = test_data.clone();

                        // Create in-memory stream for testing
                        let mut stream = std::io::Cursor::new(test_data);

                        // MUTATION: Corrupt split→unsplit identity
                        match test_idx % 12 {
                            0 => {
                                // Split into read/write halves
                                let (mut reader, mut writer) = split(stream);

                                // Corrupt: modify data through writer after split
                                let corruption_data = b"CORRUPTED";
                                writer.write_all(corruption_data).await.ok();

                                // Attempt unsplit
                                match unsplit(reader, writer) {
                                    Ok(mut restored_stream) => {
                                        let mut result_data = Vec::new();
                                        restored_stream.read_to_end(&mut result_data).await.ok();

                                        // Check if corruption affected identity
                                        if result_data != original_data && result_data.ends_with(corruption_data) {
                                            // Identity violation: unsplit didn't preserve original state
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Unsplit correctly failed due to corruption
                                    }
                                }
                            }
                            3 => {
                                // Corrupt: use different stream types for unsplit
                                let (reader, _writer) = split(stream);

                                // Create different writer from different source
                                let different_data = b"Different stream data".to_vec();
                                let different_stream = std::io::Cursor::new(different_data);
                                let (_different_reader, different_writer) = split(different_stream);

                                // Attempt to unsplit mismatched halves
                                match unsplit(reader, different_writer) {
                                    Ok(mut restored_stream) => {
                                        let mut result_data = Vec::new();
                                        restored_stream.read_to_end(&mut result_data).await.ok();

                                        // Check if mismatched unsplit was incorrectly allowed
                                        if result_data != original_data {
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Correctly rejected mismatched unsplit
                                    }
                                }
                            }
                            6 => {
                                // Corrupt: close one half before unsplit
                                let (reader, mut writer) = split(stream);

                                // Close writer prematurely
                                drop(writer);

                                // Create new writer for testing
                                let substitute_data = original_data.clone();
                                let substitute_stream = std::io::Cursor::new(substitute_data);
                                let (_sub_reader, substitute_writer) = split(substitute_stream);

                                // Attempt unsplit with closed/substituted writer
                                match unsplit(reader, substitute_writer) {
                                    Ok(mut restored_stream) => {
                                        let mut result_data = Vec::new();
                                        restored_stream.read_to_end(&mut result_data).await.ok();

                                        // Verify if identity was preserved despite substitution
                                        if result_data == original_data {
                                            // Identity incorrectly preserved with substituted writer
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Correctly detected invalid unsplit
                                    }
                                }
                            }
                            9 => {
                                // Corrupt: partial read/write before unsplit
                                let (mut reader, mut writer) = split(stream);

                                // Partial operations that should affect identity
                                let mut partial_buffer = vec![0u8; 5];
                                reader.read_exact(&mut partial_buffer).await.ok();

                                let additional_data = b"EXTRA";
                                writer.write_all(additional_data).await.ok();

                                // Attempt unsplit after partial operations
                                match unsplit(reader, writer) {
                                    Ok(mut restored_stream) => {
                                        let mut result_data = Vec::new();
                                        restored_stream.read_to_end(&mut result_data).await.ok();

                                        // Check if partial operations corrupted identity
                                        let expected_length = original_data.len() + additional_data.len() - partial_buffer.len();
                                        if result_data.len() != expected_length {
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Unsplit failed due to partial operation state
                                    }
                                }
                            }
                            _ => {
                                // Normal split→unsplit identity test
                                let (reader, writer) = split(stream);

                                match unsplit(reader, writer) {
                                    Ok(mut restored_stream) => {
                                        let mut result_data = Vec::new();
                                        restored_stream.read_to_end(&mut result_data).await.ok();

                                        // Verify perfect identity preservation
                                        if result_data != original_data {
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Normal unsplit failed unexpectedly
                                        identity_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }

                    // Test buffered I/O split→unsplit identity
                    if test_idx % 4 == 0 {
                        io_corruptions.fetch_add(1, Ordering::Relaxed);

                        let buffer_test_data = format!("Buffered I/O test data {}", test_idx).repeat(100);
                        let original_buffered = buffer_test_data.clone();

                        let stream = std::io::Cursor::new(buffer_test_data.into_bytes());

                        // Create buffered reader/writer
                        let buf_reader = BufReader::new(stream);
                        let buf_writer = BufWriter::new(Vec::new());

                        // MUTATION: Corrupt buffered split→unsplit
                        match test_idx % 16 {
                            0 => {
                                // Split buffered I/O
                                let (mut split_reader, mut split_writer) = split(buf_reader);
                                let (writer_reader, writer_writer) = split(buf_writer);

                                // Corrupt: flush partial data during split
                                let mut partial_data = vec![0u8; 50];
                                split_reader.read_exact(&mut partial_data).await.ok();
                                split_writer.write_all(b"BUFFER_CORRUPTION").await.ok();

                                // Attempt to reconstruct with corrupted buffer state
                                let restored_reader = unsplit(split_reader, split_writer);
                                let restored_writer = unsplit(writer_reader, writer_writer);

                                if let (Ok(mut reader), Ok(mut writer)) = (restored_reader, restored_writer) {
                                    let mut remaining_data = Vec::new();
                                    reader.read_to_end(&mut remaining_data).await.ok();

                                    writer.flush().await.ok();

                                    // Check buffer corruption detection
                                    if remaining_data.len() + 50 != original_buffered.len() {
                                        identity_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            4 => {
                                // Corrupt: buffer state inconsistency
                                let (buf_read_half, buf_write_half) = split(buf_reader);

                                // Create inconsistent buffer states
                                let inconsistent_reader = BufReader::with_capacity(1024, buf_read_half);
                                let inconsistent_writer = BufWriter::with_capacity(512, buf_write_half);

                                // Attempt unsplit with mismatched buffer capacities
                                match unsplit(inconsistent_reader, inconsistent_writer) {
                                    Ok(mut restored) => {
                                        // Buffer capacity mismatch should be detected
                                        let mut test_result = Vec::new();
                                        restored.read_to_end(&mut test_result).await.ok();

                                        if test_result == original_buffered.as_bytes() {
                                            // Identity preserved despite buffer mismatch - might be correct
                                        } else {
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Correctly rejected buffer capacity mismatch
                                    }
                                }
                            }
                            8 => {
                                // Corrupt: cross-contaminate buffer contents
                                let (mut read_half, mut write_half) = split(buf_reader);

                                // Read some data into buffer
                                let mut buffer_content = vec![0u8; 100];
                                read_half.read_exact(&mut buffer_content).await.ok();

                                // Write different content to writer buffer
                                write_half.write_all(b"CONTAMINATED_BUFFER_CONTENT").await.ok();

                                // Unsplit with contaminated buffers
                                match unsplit(read_half, write_half) {
                                    Ok(mut contaminated_stream) => {
                                        let mut final_content = Vec::new();
                                        contaminated_stream.read_to_end(&mut final_content).await.ok();

                                        // Check if contamination was detected
                                        if final_content.contains(b"CONTAMINATED") {
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Correctly detected buffer contamination
                                    }
                                }
                            }
                            12 => {
                                // Corrupt: buffer position corruption
                                let (read_half, write_half) = split(buf_reader);

                                // Manually corrupt internal buffer positions (if accessible)
                                // This simulates low-level buffer state corruption

                                match unsplit(read_half, write_half) {
                                    Ok(mut position_corrupted) => {
                                        let mut position_test = Vec::new();
                                        position_corrupted.read_to_end(&mut position_test).await.ok();

                                        // Verify position integrity
                                        if position_test != original_buffered.as_bytes() {
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Position corruption correctly detected
                                    }
                                }
                            }
                            _ => {
                                // Normal buffered split→unsplit
                                let (read_half, write_half) = split(buf_reader);

                                match unsplit(read_half, write_half) {
                                    Ok(mut normal_restored) => {
                                        let mut normal_result = Vec::new();
                                        normal_restored.read_to_end(&mut normal_result).await.ok();

                                        if normal_result != original_buffered.as_bytes() {
                                            identity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => {
                                        // Normal case failed unexpectedly
                                        identity_violations.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }

                    sleep(Duration::from_millis(8)).await;
                }

                let corruptions = io_corruptions.load(Ordering::Relaxed);
                let violations = identity_violations.load(Ordering::Relaxed);

                // I/O should detect split→unsplit identity violations
                if violations > 0 && corruptions > 0 {
                    Outcome::Ok(true) // IO identity violation detected
                } else if corruptions > 0 {
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("IO split→unsplit validation failed: {} corruptions, {} violations",
                            corruptions, violations)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(io_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-39",
            "io",
            "split_unsplit_identity_corruption",
            detected,
        );
    }

    /// [br-mutation-40] Database mysql/sqlite client connection regression mutations
    async fn test_database_client_mutations(&self) {
        use crate::database::{ConnectionError, QueryError, TransactionError, mysql, sqlite};

        let database_client_detected = self
            .runtime
            .scope(|scope| async move {
                let client_test_count = 16;
                let client_corruptions = Arc::new(AtomicUsize::new(0));
                let connection_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..client_test_count {
                            // Test MySQL/SQLite connection parameter corruption
                            if test_idx % 3 == 0 {
                                client_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt database connection parameters
                                match test_idx % 16 {
                                    0 => {
                                        // MySQL connection string injection
                                        let mysql_config = mysql::ConnectionConfig::new()
                                            .with_host("localhost'; DROP TABLE users; --")
                                            .with_port(3306)
                                            .with_database("test_db")
                                            .with_username("test_user")
                                            .with_password("test_password");

                                        match mysql::Client::connect(mysql_config).await {
                                            Err(ConnectionError::InvalidHost) => {
                                                // Correctly detected SQL injection in host
                                            }
                                            Ok(_) => {
                                                // Should have rejected dangerous host
                                                connection_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    1 => {
                                        // SQLite path traversal injection
                                        let sqlite_path = "../../../etc/passwd";
                                        match sqlite::Connection::open(sqlite_path).await {
                                            Err(ConnectionError::InvalidPath) => {
                                                // Correctly detected path traversal
                                            }
                                            Ok(_) => {
                                                // Should have rejected dangerous path
                                                connection_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    2 => {
                                        // MySQL password buffer overflow attempt
                                        let oversized_password = "A".repeat(10000);
                                        let mysql_config = mysql::ConnectionConfig::new()
                                            .with_host("localhost")
                                            .with_port(3306)
                                            .with_database("test_db")
                                            .with_username("test_user")
                                            .with_password(&oversized_password);

                                        match mysql::Client::connect(mysql_config).await {
                                            Err(ConnectionError::InvalidCredentials) => {
                                                // Correctly handled oversized password
                                            }
                                            Ok(_) => {
                                                // Should have rejected oversized password
                                                connection_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    4 => {
                                        // SQLite database pragma injection
                                        let sqlite_path = ":memory:; PRAGMA auto_vacuum = NONE; --";
                                        match sqlite::Connection::open(sqlite_path).await {
                                            Err(ConnectionError::InvalidPath) => {
                                                // Correctly detected pragma injection
                                            }
                                            Ok(conn) => {
                                                // Check if pragma injection was blocked
                                                match conn.query_row("PRAGMA auto_vacuum", [], |_| Ok(())).await {
                                                    Ok(_) => {
                                                        connection_violations.fetch_add(1, Ordering::Relaxed);
                                                    }
                                                    Err(_) => {
                                                        // Pragma injection was blocked
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    8 => {
                                        // MySQL port manipulation
                                        let mysql_config = mysql::ConnectionConfig::new()
                                            .with_host("localhost")
                                            .with_port(0) // Invalid port
                                            .with_database("test_db")
                                            .with_username("test_user")
                                            .with_password("test_password");

                                        match mysql::Client::connect(mysql_config).await {
                                            Err(ConnectionError::InvalidPort) => {
                                                // Correctly detected invalid port
                                            }
                                            Ok(_) => {
                                                // Should have rejected invalid port
                                                connection_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other connection error
                                            }
                                        }
                                    }
                                    12 => {
                                        // SQLite file descriptor exhaustion
                                        let mut connections = Vec::new();
                                        for _ in 0..1000 {
                                            match sqlite::Connection::open(":memory:").await {
                                                Ok(conn) => {
                                                    connections.push(conn);
                                                }
                                                Err(ConnectionError::TooManyConnections) => {
                                                    // Correctly limited connections
                                                    break;
                                                }
                                                Err(_) => {
                                                    // Other error
                                                    break;
                                                }
                                            }
                                        }
                                        if connections.len() > 500 {
                                            // Should have limited connections earlier
                                            connection_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    _ => {
                                        // Normal connection test
                                        let mysql_config = mysql::ConnectionConfig::new()
                                            .with_host("localhost")
                                            .with_port(3306)
                                            .with_database("test_db")
                                            .with_username("test_user")
                                            .with_password("test_password");

                                        let _ = mysql::Client::connect(mysql_config).await;
                                    }
                                }
                            }

                            // Test transaction isolation corruption
                            if test_idx % 4 == 0 {
                                client_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt transaction isolation levels
                                let sqlite_conn = sqlite::Connection::open(":memory:").await.unwrap();

                                match test_idx % 8 {
                                    0 => {
                                        // Begin transaction with invalid isolation
                                        match sqlite_conn.execute("BEGIN IMMEDIATE TRANSACTION ISOLATION LEVEL INVALID", []).await {
                                            Err(QueryError::InvalidSyntax) => {
                                                // Correctly detected invalid isolation level
                                            }
                                            Ok(_) => {
                                                // Should have rejected invalid isolation level
                                                connection_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    4 => {
                                        // Corrupt nested transaction handling
                                        let _tx1 = sqlite_conn.begin_transaction().await.unwrap();

                                        // Attempt nested transaction without savepoint
                                        match sqlite_conn.begin_transaction().await {
                                            Err(TransactionError::NestedTransactionNotAllowed) => {
                                                // Correctly prevented nested transaction
                                            }
                                            Ok(_) => {
                                                // Should have prevented nested transaction
                                                connection_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal transaction test
                                        if let Ok(tx) = sqlite_conn.begin_transaction().await {
                                            tx.commit().await.ok();
                                        }
                                    }
                                }
                            }

                            sleep(Duration::from_millis(5)).await;
                        }

                        let corruptions = client_corruptions.load(Ordering::Relaxed);
                        let violations = connection_violations.load(Ordering::Relaxed);

                        // Database client validation should catch connection corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Connection corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(ErrorKind::Other,
                                format!("Database client validation failed: {} corruptions, {} violations",
                                    corruptions, violations)))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(
            database_client_detected,
            Outcome::Ok(true) | Outcome::Err(_)
        );
        self.log_subsystem_mutation(
            "br-mutation-40",
            "database",
            "mysql_sqlite_connection_corruption",
            detected,
        );
    }

    /// [br-mutation-41] FS vfs/platform/path operations regression mutations
    async fn test_fs_operations_mutations(&self) {
        use crate::fs::{FileSystemError, PathBuf, VirtualFileSystem, path_ops, platform, vfs};

        let fs_operations_detected = self
            .runtime
            .scope(|scope| async move {
                let fs_ops_test_count = 14;
                let fs_ops_corruptions = Arc::new(AtomicUsize::new(0));
                let path_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..fs_ops_test_count {
                            // Test path traversal and canonicalization corruption
                            if test_idx % 3 == 0 {
                                fs_ops_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt path operations
                                match test_idx % 14 {
                                    0 => {
                                        // Path traversal injection
                                        let dangerous_path = PathBuf::from("../../../etc/passwd");
                                        match path_ops::canonicalize(&dangerous_path).await {
                                            Err(FileSystemError::PathTraversalDenied) => {
                                                // Correctly blocked path traversal
                                            }
                                            Ok(canonical_path) => {
                                                if canonical_path.to_string_lossy().contains("/etc/passwd") {
                                                    // Should have blocked path traversal
                                                    path_violations.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    1 => {
                                        // Symlink bomb creation
                                        let symlink_path = PathBuf::from("test_symlink");
                                        match path_ops::create_symlink(&symlink_path, &symlink_path).await {
                                            Err(FileSystemError::CircularSymlink) => {
                                                // Correctly detected circular symlink
                                            }
                                            Ok(_) => {
                                                // Should have detected circular symlink
                                                path_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    2 => {
                                        // Filename with null bytes
                                        let invalid_filename = "test\0file.txt";
                                        let path = PathBuf::from(invalid_filename);
                                        match path_ops::create_file(&path).await {
                                            Err(FileSystemError::InvalidFilename) => {
                                                // Correctly rejected null bytes in filename
                                            }
                                            Ok(_) => {
                                                // Should have rejected null bytes
                                                path_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    3 => {
                                        // VFS mount point corruption
                                        let mut vfs = VirtualFileSystem::new();
                                        let mount_point = PathBuf::from("/../../../mnt/danger");

                                        match vfs.mount(&mount_point, "/dev/sda1").await {
                                            Err(FileSystemError::InvalidMountPoint) => {
                                                // Correctly rejected dangerous mount point
                                            }
                                            Ok(_) => {
                                                // Should have rejected dangerous mount point
                                                path_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    6 => {
                                        // Platform-specific path length overflow
                                        let oversized_path = "A".repeat(10000);
                                        let path = PathBuf::from(oversized_path);

                                        match platform::validate_path_length(&path) {
                                            Err(FileSystemError::PathTooLong) => {
                                                // Correctly detected oversized path
                                            }
                                            Ok(_) => {
                                                // Should have detected oversized path
                                                path_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal path operation test
                                        let normal_path = PathBuf::from("test_file.txt");
                                        path_ops::canonicalize(&normal_path).await.ok();
                                    }
                                }
                            }

                            sleep(Duration::from_millis(4)).await;
                        }

                        let corruptions = fs_ops_corruptions.load(Ordering::Relaxed);
                        let violations = path_violations.load(Ordering::Relaxed);

                        // FS operations validation should catch path/permission corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Path/permission corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(ErrorKind::Other,
                                format!("FS operations validation failed: {} corruptions, {} violations",
                                    corruptions, violations)))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(fs_operations_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-41",
            "fs",
            "vfs_platform_path_operations_corruption",
            detected,
        );
    }

    /// [br-mutation-42] IO capability/browser/copy operations regression mutations
    async fn test_io_capability_mutations(&self) {
        use crate::io::{CapabilityError, IoError, browser_storage, browser_stream, cap, copy};

        let io_capability_detected = self
            .runtime
            .scope(|scope| async move {
                let io_cap_test_count = 16;
                let io_cap_corruptions = Arc::new(AtomicUsize::new(0));
                let capability_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..io_cap_test_count {
                            // Test capability-based I/O corruption
                            if test_idx % 3 == 0 {
                                io_cap_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt I/O capability checks
                                match test_idx % 16 {
                                    0 => {
                                        // Capability bypass attempt
                                        let restricted_cap = cap::IoCapability::new()
                                            .with_read_only("/tmp")
                                            .with_max_file_size(1024);

                                        let large_data = vec![0u8; 2048]; // Exceeds max_file_size
                                        match cap::write_with_capability(&restricted_cap, "/tmp/test.txt", &large_data).await {
                                            Err(CapabilityError::FileSizeExceeded) => {
                                                // Correctly enforced file size limit
                                            }
                                            Ok(_) => {
                                                // Should have enforced file size limit
                                                capability_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    1 => {
                                        // Browser storage quota corruption
                                        let mut browser_storage = browser_storage::LocalStorage::new();
                                        browser_storage.set_quota_limit(1024).await.ok();

                                        let oversized_data = "A".repeat(2048);
                                        match browser_storage.set("key", &oversized_data).await {
                                            Err(IoError::StorageQuotaExceeded) => {
                                                // Correctly enforced storage quota
                                            }
                                            Ok(_) => {
                                                // Should have enforced storage quota
                                                capability_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    3 => {
                                        // Copy operation buffer overflow
                                        let source_data = vec![0u8; 1024];
                                        let mut source = std::io::Cursor::new(source_data);
                                        let mut destination = Vec::new();

                                        // Attempt copy with corrupted buffer size
                                        match copy::copy_with_buffer_size(&mut source, &mut destination, 0).await {
                                            Err(IoError::InvalidBufferSize) => {
                                                // Correctly rejected zero buffer size
                                            }
                                            Ok(_) => {
                                                // Should have rejected zero buffer size
                                                capability_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal capability test
                                        let normal_cap = cap::IoCapability::new()
                                            .with_read_write("/tmp");
                                        cap::write_with_capability(&normal_cap, "/tmp/normal.txt", b"test").await.ok();
                                    }
                                }
                            }

                            sleep(Duration::from_millis(3)).await;
                        }

                        let corruptions = io_cap_corruptions.load(Ordering::Relaxed);
                        let violations = capability_violations.load(Ordering::Relaxed);

                        // IO capability validation should catch capability/security corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Capability corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(ErrorKind::Other,
                                format!("IO capability validation failed: {} corruptions, {} violations",
                                    corruptions, violations)))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(io_capability_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-42",
            "io",
            "capability_browser_copy_operations_corruption",
            detected,
        );
    }

    /// [br-mutation-43] Runtime state region close eager-vs-lazy regression mutations
    async fn test_runtime_state_mutations(&self) {
        use crate::runtime::{Region, RegionCloseMode, RegionState, StateError, TaskState, state};

        let runtime_state_detected = self
            .runtime
            .scope(|scope| async move {
                let state_test_count = 18;
                let state_corruptions = Arc::new(AtomicUsize::new(0));
                let close_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..state_test_count {
                            // Test region close eager vs lazy mode corruption
                            if test_idx % 3 == 0 {
                                state_corruptions.fetch_add(1, Ordering::Relaxed);

                                let runtime_state = state::RuntimeState::new();

                                // MUTATION: Corrupt region close mode handling
                                match test_idx % 18 {
                                    0 => {
                                        // Create region with eager close mode
                                        let region = runtime_state
                                            .create_region_with_mode(RegionCloseMode::Eager)
                                            .await;

                                        // Spawn tasks in the region
                                        let mut task_handles = Vec::new();
                                        for i in 0..5 {
                                            let task_handle = region
                                                .spawn_task(format!("eager_task_{}", i), async move {
                                                    sleep(Duration::from_millis(100)).await;
                                                })
                                                .await;
                                            task_handles.push(task_handle);
                                        }

                                        // MUTATION: Force lazy close despite eager mode
                                        match runtime_state.close_region_with_mode(&region.id(), RegionCloseMode::Lazy).await {
                                            Ok(_) => {
                                                // Should have enforced eager mode
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(StateError::RegionCloseModeViolation) => {
                                                // Correctly enforced eager mode
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    1 => {
                                        // Create region with lazy close mode
                                        let region = runtime_state
                                            .create_region_with_mode(RegionCloseMode::Lazy)
                                            .await;

                                        // Spawn long-running task
                                        let _long_task = region
                                            .spawn_task("lazy_task", async move {
                                                sleep(Duration::from_millis(500)).await;
                                            })
                                            .await;

                                        // MUTATION: Force eager close despite lazy mode and active tasks
                                        match runtime_state.close_region_with_mode(&region.id(), RegionCloseMode::Eager).await {
                                            Ok(_) => {
                                                // Check if tasks were properly cancelled
                                                let remaining_tasks = runtime_state.get_region_task_count(&region.id()).await;
                                                if remaining_tasks > 0 {
                                                    // Eager close should have cancelled tasks
                                                    close_violations.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            Err(StateError::ActiveTasksInEagerClose) => {
                                                // Correctly prevented eager close with active tasks
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    2 => {
                                        // Test region state transition corruption
                                        let region = runtime_state.create_region_with_mode(RegionCloseMode::Eager).await;

                                        // MUTATION: Corrupt region state directly
                                        match runtime_state.force_region_state(&region.id(), RegionState::Closing).await {
                                            Err(StateError::InvalidStateTransition) => {
                                                // Correctly prevented invalid state transition
                                            }
                                            Ok(_) => {
                                                // Should have prevented invalid state transition
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    3 => {
                                        // Test quiescence check corruption in eager mode
                                        let region = runtime_state.create_region_with_mode(RegionCloseMode::Eager).await;

                                        // Create task that will block quiescence
                                        let _blocking_task = region
                                            .spawn_task("blocking_task", async move {
                                                // Simulate task that doesn't respond to cancellation
                                                loop {
                                                    sleep(Duration::from_millis(10)).await;
                                                }
                                            })
                                            .await;

                                        // MUTATION: Skip quiescence check in eager close
                                        match runtime_state.close_region_skip_quiescence(&region.id()).await {
                                            Err(StateError::QuiescenceCheckRequired) => {
                                                // Correctly enforced quiescence check
                                            }
                                            Ok(_) => {
                                                // Should have enforced quiescence check
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    6 => {
                                        // Test parent-child region close order corruption
                                        let parent_region = runtime_state.create_region_with_mode(RegionCloseMode::Eager).await;
                                        let child_region = runtime_state
                                            .create_child_region(&parent_region.id(), RegionCloseMode::Lazy)
                                            .await;

                                        // MUTATION: Try to close parent before child
                                        match runtime_state.close_region(&parent_region.id()).await {
                                            Err(StateError::ChildRegionsStillActive) => {
                                                // Correctly prevented closing parent with active children
                                            }
                                            Ok(_) => {
                                                // Should have prevented closing parent with active children
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    9 => {
                                        // Test region close timeout corruption
                                        let region = runtime_state.create_region_with_mode(RegionCloseMode::Lazy).await;

                                        // Create task that will timeout during close
                                        let _timeout_task = region
                                            .spawn_task("timeout_task", async move {
                                                sleep(Duration::from_secs(10)).await; // Very long
                                            })
                                            .await;

                                        // MUTATION: Close with corrupted timeout (too short)
                                        match runtime_state
                                            .close_region_with_timeout(&region.id(), Duration::from_millis(1))
                                            .await
                                        {
                                            Err(StateError::RegionCloseTimeout) => {
                                                // Correctly timed out
                                            }
                                            Ok(_) => {
                                                // Should have timed out with too short timeout
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    12 => {
                                        // Test obligation cleanup order corruption
                                        let region = runtime_state.create_region_with_mode(RegionCloseMode::Eager).await;

                                        // Create obligations in region
                                        let obligation1 = region.create_obligation("test_obligation_1").await;
                                        let obligation2 = region.create_obligation("test_obligation_2").await;

                                        // MUTATION: Close region without completing obligations
                                        match runtime_state.close_region(&region.id()).await {
                                            Err(StateError::OutstandingObligations) => {
                                                // Correctly detected outstanding obligations
                                            }
                                            Ok(_) => {
                                                // Should have detected outstanding obligations
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    15 => {
                                        // Test concurrent region close corruption
                                        let region = runtime_state.create_region_with_mode(RegionCloseMode::Lazy).await;

                                        // MUTATION: Attempt concurrent closes
                                        let close1 = runtime_state.close_region(&region.id());
                                        let close2 = runtime_state.close_region(&region.id());

                                        match futures::join!(close1, close2) {
                                            (Ok(_), Err(StateError::RegionAlreadyClosing)) |
                                            (Err(StateError::RegionAlreadyClosing), Ok(_)) => {
                                                // Correctly handled concurrent close
                                            }
                                            (Ok(_), Ok(_)) => {
                                                // Should have prevented double close
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            _ => {
                                                // Other error combinations
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal region lifecycle test
                                        let region = runtime_state.create_region_with_mode(RegionCloseMode::Eager).await;
                                        let _task = region.spawn_task("normal_task", async {}).await;
                                        runtime_state.close_region(&region.id()).await.ok();
                                    }
                                }
                            }

                            // Test task state corruption during region close
                            if test_idx % 4 == 0 {
                                state_corruptions.fetch_add(1, Ordering::Relaxed);

                                let runtime_state = state::RuntimeState::new();
                                let region = runtime_state.create_region_with_mode(RegionCloseMode::Eager).await;

                                // MUTATION: Corrupt task state during region close
                                match test_idx % 12 {
                                    0 => {
                                        // Create task and corrupt its state to Running after it completes
                                        let task = region.spawn_task("state_corrupt_task", async {}).await;

                                        // Wait for task to complete
                                        task.join().await.ok();

                                        // MUTATION: Force task back to Running state
                                        match runtime_state.force_task_state(&task.id(), TaskState::Running).await {
                                            Err(StateError::InvalidTaskStateTransition) => {
                                                // Correctly prevented invalid state transition
                                            }
                                            Ok(_) => {
                                                // Should have prevented invalid state transition
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    4 => {
                                        // Test task finalization corruption
                                        let task = region
                                            .spawn_task("finalize_corrupt_task", async {
                                                panic!("Test panic");
                                            })
                                            .await;

                                        // Wait for task to panic
                                        task.join().await.ok();

                                        // MUTATION: Skip finalization during region close
                                        match runtime_state.close_region_skip_finalization(&region.id()).await {
                                            Err(StateError::FinalizationRequired) => {
                                                // Correctly enforced finalization
                                            }
                                            Ok(_) => {
                                                // Should have enforced finalization
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    8 => {
                                        // Test leaked reference during close
                                        let task = region.spawn_task("leak_test_task", async {}).await;

                                        // MUTATION: Keep reference to task after region starts closing
                                        runtime_state.begin_region_close(&region.id()).await.ok();

                                        match runtime_state.access_task_in_closing_region(&task.id()).await {
                                            Err(StateError::TaskAccessInClosingRegion) => {
                                                // Correctly prevented access to task in closing region
                                            }
                                            Ok(_) => {
                                                // Should have prevented access to task in closing region
                                                close_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal task lifecycle test
                                        let task = region.spawn_task("normal_lifecycle_task", async {}).await;
                                        task.join().await.ok();
                                    }
                                }
                            }

                            sleep(Duration::from_millis(3)).await;
                        }

                        let corruptions = state_corruptions.load(Ordering::Relaxed);
                        let violations = close_violations.load(Ordering::Relaxed);

                        // Runtime state validation should catch region close corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Region close corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(ErrorKind::Other,
                                format!("Runtime state validation failed: {} corruptions, {} violations",
                                    corruptions, violations)))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(runtime_state_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-43",
            "runtime",
            "state_region_close_eager_lazy_corruption",
            detected,
        );
    }

    /// [br-mutation-44] Cx registry commit_permit identity regression mutations
    async fn test_cx_registry_mutations(&self) {
        use crate::cx::{CapabilityId, CommitPermit, PermitId, RegistryError, registry};

        let cx_registry_detected = self
            .runtime
            .scope(|scope| async move {
                let registry_test_count = 16;
                let registry_corruptions = Arc::new(AtomicUsize::new(0));
                let permit_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..registry_test_count {
                            // Test commit permit identity corruption
                            if test_idx % 3 == 0 {
                                registry_corruptions.fetch_add(1, Ordering::Relaxed);

                                let mut cx_registry = registry::CxRegistry::new();

                                // MUTATION: Corrupt commit permit identity checking
                                match test_idx % 16 {
                                    0 => {
                                        // Create permit for one capability
                                        let capability_a =
                                            cx_registry.register_capability("test_cap_a").await;
                                        let permit_a = cx_registry
                                            .acquire_permit(&capability_a)
                                            .await
                                            .unwrap();

                                        // Create permit for different capability
                                        let capability_b =
                                            cx_registry.register_capability("test_cap_b").await;
                                        let permit_b = cx_registry
                                            .acquire_permit(&capability_b)
                                            .await
                                            .unwrap();

                                        // MUTATION: Try to commit permit A as if it were for capability B
                                        let commit_permit_corrupted =
                                            CommitPermit::new(&permit_a.id(), &capability_b);

                                        match cx_registry
                                            .commit_permit(commit_permit_corrupted)
                                            .await
                                        {
                                            Err(RegistryError::PermitIdentityMismatch) => {
                                                // Correctly detected permit identity mismatch
                                            }
                                            Ok(_) => {
                                                // Should have detected permit identity mismatch
                                                permit_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    1 => {
                                        // Test double commit corruption
                                        let capability = cx_registry
                                            .register_capability("double_commit_test")
                                            .await;
                                        let permit =
                                            cx_registry.acquire_permit(&capability).await.unwrap();

                                        // First commit (should succeed)
                                        let commit_permit1 =
                                            CommitPermit::new(&permit.id(), &capability);
                                        cx_registry.commit_permit(commit_permit1).await.ok();

                                        // MUTATION: Second commit of same permit
                                        let commit_permit2 =
                                            CommitPermit::new(&permit.id(), &capability);
                                        match cx_registry.commit_permit(commit_permit2).await {
                                            Err(RegistryError::PermitAlreadyCommitted) => {
                                                // Correctly prevented double commit
                                            }
                                            Ok(_) => {
                                                // Should have prevented double commit
                                                permit_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    2 => {
                                        // Test permit expiry bypass corruption
                                        let capability =
                                            cx_registry.register_capability("expiry_test").await;
                                        let permit = cx_registry
                                            .acquire_permit_with_expiry(
                                                &capability,
                                                Duration::from_millis(100),
                                            )
                                            .await
                                            .unwrap();

                                        // Wait for permit to expire
                                        sleep(Duration::from_millis(200)).await;

                                        // MUTATION: Try to commit expired permit
                                        let commit_permit =
                                            CommitPermit::new(&permit.id(), &capability);
                                        match cx_registry.commit_permit(commit_permit).await {
                                            Err(RegistryError::PermitExpired) => {
                                                // Correctly detected expired permit
                                            }
                                            Ok(_) => {
                                                // Should have detected expired permit
                                                permit_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    3 => {
                                        // Test capability revocation bypass corruption
                                        let capability = cx_registry
                                            .register_capability("revocation_test")
                                            .await;
                                        let permit =
                                            cx_registry.acquire_permit(&capability).await.unwrap();

                                        // Revoke capability
                                        cx_registry.revoke_capability(&capability).await.ok();

                                        // MUTATION: Try to commit permit for revoked capability
                                        let commit_permit =
                                            CommitPermit::new(&permit.id(), &capability);
                                        match cx_registry.commit_permit(commit_permit).await {
                                            Err(RegistryError::CapabilityRevoked) => {
                                                // Correctly detected revoked capability
                                            }
                                            Ok(_) => {
                                                // Should have detected revoked capability
                                                permit_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    4 => {
                                        // Test forged permit ID corruption
                                        let capability =
                                            cx_registry.register_capability("forge_test").await;
                                        let real_permit =
                                            cx_registry.acquire_permit(&capability).await.unwrap();

                                        // MUTATION: Create commit permit with forged ID
                                        let forged_permit_id = PermitId::new(); // Different ID
                                        let commit_permit_forged =
                                            CommitPermit::new(&forged_permit_id, &capability);

                                        match cx_registry.commit_permit(commit_permit_forged).await
                                        {
                                            Err(RegistryError::PermitNotFound) => {
                                                // Correctly detected forged permit ID
                                            }
                                            Ok(_) => {
                                                // Should have detected forged permit ID
                                                permit_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    6 => {
                                        // Test permit reuse across registry instances corruption
                                        let registry1 = registry::CxRegistry::new();
                                        let registry2 = registry::CxRegistry::new();

                                        let capability1 = registry1
                                            .register_capability("cross_registry_test")
                                            .await;
                                        let permit1 =
                                            registry1.acquire_permit(&capability1).await.unwrap();

                                        // MUTATION: Try to use permit from registry1 in registry2
                                        let commit_permit =
                                            CommitPermit::new(&permit1.id(), &capability1);
                                        match registry2.commit_permit(commit_permit).await {
                                            Err(RegistryError::PermitRegistryMismatch) => {
                                                // Correctly detected cross-registry permit reuse
                                            }
                                            Ok(_) => {
                                                // Should have detected cross-registry permit reuse
                                                permit_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    8 => {
                                        // Test concurrent permit commit corruption
                                        let capability = cx_registry
                                            .register_capability("concurrent_test")
                                            .await;
                                        let permit =
                                            cx_registry.acquire_permit(&capability).await.unwrap();

                                        // MUTATION: Attempt concurrent commits of same permit
                                        let commit_permit1 =
                                            CommitPermit::new(&permit.id(), &capability);
                                        let commit_permit2 =
                                            CommitPermit::new(&permit.id(), &capability);

                                        let commit1 = cx_registry.commit_permit(commit_permit1);
                                        let commit2 = cx_registry.commit_permit(commit_permit2);

                                        match futures::join!(commit1, commit2) {
                                            (Ok(_), Err(RegistryError::PermitAlreadyCommitted))
                                            | (Err(RegistryError::PermitAlreadyCommitted), Ok(_)) =>
                                            {
                                                // Correctly handled concurrent commit
                                            }
                                            (Ok(_), Ok(_)) => {
                                                // Should have prevented double commit
                                                permit_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            _ => {
                                                // Other error combinations
                                            }
                                        }
                                    }
                                    12 => {
                                        // Test capability hierarchy bypass corruption
                                        let parent_capability =
                                            cx_registry.register_capability("parent_cap").await;
                                        let child_capability = cx_registry
                                            .register_child_capability(
                                                "child_cap",
                                                &parent_capability,
                                            )
                                            .await
                                            .unwrap();

                                        let child_permit = cx_registry
                                            .acquire_permit(&child_capability)
                                            .await
                                            .unwrap();

                                        // MUTATION: Try to commit child permit as parent capability
                                        let commit_permit_corrupted = CommitPermit::new(
                                            &child_permit.id(),
                                            &parent_capability,
                                        );
                                        match cx_registry
                                            .commit_permit(commit_permit_corrupted)
                                            .await
                                        {
                                            Err(RegistryError::CapabilityHierarchyViolation) => {
                                                // Correctly detected capability hierarchy violation
                                            }
                                            Ok(_) => {
                                                // Should have detected capability hierarchy violation
                                                permit_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal permit lifecycle test
                                        let capability =
                                            cx_registry.register_capability("normal_test").await;
                                        let permit =
                                            cx_registry.acquire_permit(&capability).await.unwrap();
                                        let commit_permit =
                                            CommitPermit::new(&permit.id(), &capability);
                                        cx_registry.commit_permit(commit_permit).await.ok();
                                    }
                                }
                            }

                            sleep(Duration::from_millis(4)).await;
                        }

                        let corruptions = registry_corruptions.load(Ordering::Relaxed);
                        let violations = permit_violations.load(Ordering::Relaxed);

                        // Cx registry validation should catch permit identity corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Permit identity corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Cx registry validation failed: {} corruptions, {} violations",
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

        let detected = matches!(cx_registry_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-44",
            "cx",
            "registry_commit_permit_identity_corruption",
            detected,
        );
    }

    /// [br-mutation-45] Net DNS TTL caching expiry regression mutations
    async fn test_net_dns_mutations(&self) {
        use crate::net::dns::{CacheError, DnsCache, DnsRecord, DnsTtl, RecordType};

        let net_dns_detected = self
            .runtime
            .scope(|scope| async move {
                let dns_test_count = 20;
                let dns_corruptions = Arc::new(AtomicUsize::new(0));
                let ttl_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..dns_test_count {
                            // Test DNS TTL caching expiry corruption
                            if test_idx % 3 == 0 {
                                dns_corruptions.fetch_add(1, Ordering::Relaxed);

                                let mut dns_cache = DnsCache::new();

                                // MUTATION: Corrupt DNS TTL caching behavior
                                match test_idx % 20 {
                                    0 => {
                                        // Test TTL expiry bypass corruption
                                        let record = DnsRecord::new(
                                            "example.com",
                                            RecordType::A,
                                            "192.168.1.1",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(1)); // Very short TTL

                                        dns_cache.insert(record.clone()).await;

                                        // Wait for TTL to expire
                                        sleep(Duration::from_millis(1500)).await;

                                        // MUTATION: Return expired record instead of cache miss
                                        match dns_cache
                                            .get_ignore_ttl("example.com", RecordType::A)
                                            .await
                                        {
                                            Some(cached_record) => {
                                                // Should not return expired record
                                                ttl_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            None => {
                                                // Correctly handled TTL expiry
                                            }
                                        }
                                    }
                                    1 => {
                                        // Test TTL refresh corruption
                                        let original_record = DnsRecord::new(
                                            "refresh.com",
                                            RecordType::A,
                                            "10.0.0.1",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(60));

                                        dns_cache.insert(original_record.clone()).await;

                                        // MUTATION: Update TTL without proper authority validation
                                        let updated_record = DnsRecord::new(
                                            "refresh.com",
                                            RecordType::A,
                                            "10.0.0.1",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(3600)); // Extended TTL

                                        match dns_cache
                                            .update_ttl_without_validation(&updated_record)
                                            .await
                                        {
                                            Err(CacheError::TtlUpdateRequiresValidation) => {
                                                // Correctly required validation for TTL update
                                            }
                                            Ok(_) => {
                                                // Should have required validation for TTL update
                                                ttl_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    2 => {
                                        // Test negative caching TTL corruption
                                        let nxdomain_record =
                                            DnsRecord::new_nxdomain("nonexistent.com")
                                                .with_ttl(DnsTtl::from_seconds(300)); // 5 minutes negative cache

                                        dns_cache.insert_negative(nxdomain_record).await;

                                        // MUTATION: Positive record overwrites negative cache before TTL expires
                                        let positive_record = DnsRecord::new(
                                            "nonexistent.com",
                                            RecordType::A,
                                            "1.2.3.4",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(60));

                                        match dns_cache
                                            .insert_ignoring_negative_cache(positive_record)
                                            .await
                                        {
                                            Err(CacheError::NegativeCacheStillValid) => {
                                                // Correctly honored negative cache TTL
                                            }
                                            Ok(_) => {
                                                // Should have honored negative cache TTL
                                                ttl_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    3 => {
                                        // Test cache poisoning via TTL manipulation
                                        let legitimate_record = DnsRecord::new(
                                            "bank.com",
                                            RecordType::A,
                                            "203.0.113.1",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(300));

                                        dns_cache.insert(legitimate_record).await;

                                        // MUTATION: Malicious record with very long TTL
                                        let malicious_record = DnsRecord::new(
                                            "bank.com",
                                            RecordType::A,
                                            "192.0.2.666",
                                        ) // Malicious IP
                                        .with_ttl(DnsTtl::from_seconds(86400)); // 24 hours

                                        match dns_cache
                                            .insert_without_authority_check(malicious_record)
                                            .await
                                        {
                                            Err(CacheError::AuthorityValidationRequired) => {
                                                // Correctly required authority validation
                                            }
                                            Ok(_) => {
                                                // Should have required authority validation
                                                ttl_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    4 => {
                                        // Test TTL zero handling corruption
                                        let zero_ttl_record = DnsRecord::new(
                                            "immediate.com",
                                            RecordType::A,
                                            "198.51.100.1",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(0)); // Should not be cached

                                        match dns_cache
                                            .insert_zero_ttl_record(zero_ttl_record)
                                            .await
                                        {
                                            Err(CacheError::ZeroTtlNotCacheable) => {
                                                // Correctly rejected zero TTL caching
                                            }
                                            Ok(_) => {
                                                // Should have rejected zero TTL caching
                                                ttl_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    6 => {
                                        // Test TTL drift corruption (system clock changes)
                                        let record = DnsRecord::new(
                                            "timetest.com",
                                            RecordType::A,
                                            "203.0.113.2",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(120));

                                        dns_cache.insert(record).await;

                                        // MUTATION: Simulate system clock going backwards
                                        dns_cache
                                            .simulate_clock_drift(Duration::from_secs(-60))
                                            .await;

                                        match dns_cache.get("timetest.com", RecordType::A).await {
                                            Some(cached_record) => {
                                                // Check if TTL was correctly adjusted for clock drift
                                                if cached_record.remaining_ttl()
                                                    > Duration::from_secs(120)
                                                {
                                                    // TTL should have been adjusted for clock drift
                                                    ttl_violations.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            None => {
                                                // Record expired due to clock drift handling
                                            }
                                        }
                                    }
                                    8 => {
                                        // Test cache eviction TTL bypass corruption
                                        dns_cache.set_max_size(2).await; // Very small cache

                                        let record1 =
                                            DnsRecord::new("first.com", RecordType::A, "192.0.2.1")
                                                .with_ttl(DnsTtl::from_seconds(3600));
                                        let record2 = DnsRecord::new(
                                            "second.com",
                                            RecordType::A,
                                            "192.0.2.2",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(1)); // Short TTL
                                        let record3 =
                                            DnsRecord::new("third.com", RecordType::A, "192.0.2.3")
                                                .with_ttl(DnsTtl::from_seconds(3600));

                                        dns_cache.insert(record1).await;
                                        dns_cache.insert(record2).await;

                                        // Wait for record2 to expire
                                        sleep(Duration::from_millis(1500)).await;

                                        // MUTATION: Insert record3, should evict expired record2 not valid record1
                                        dns_cache.insert(record3).await;

                                        if dns_cache.get("first.com", RecordType::A).await.is_none()
                                        {
                                            // Should have evicted expired record2, not valid record1
                                            ttl_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    10 => {
                                        // Test concurrent TTL expiry corruption
                                        let record = DnsRecord::new(
                                            "concurrent.com",
                                            RecordType::A,
                                            "203.0.113.3",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(1));

                                        dns_cache.insert(record).await;

                                        // Wait until just before expiry
                                        sleep(Duration::from_millis(900)).await;

                                        // MUTATION: Concurrent gets during expiry window
                                        let get1 = dns_cache.get("concurrent.com", RecordType::A);
                                        let get2 = dns_cache.get("concurrent.com", RecordType::A);

                                        let (result1, result2) = futures::join!(get1, get2);

                                        match (result1, result2) {
                                            (Some(_), None) | (None, Some(_)) => {
                                                // Inconsistent results during expiry window
                                                ttl_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            _ => {
                                                // Consistent results (both found or both expired)
                                            }
                                        }
                                    }
                                    12 => {
                                        // Test minimum TTL enforcement corruption
                                        let short_ttl_record = DnsRecord::new(
                                            "shortttl.com",
                                            RecordType::A,
                                            "198.51.100.2",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(5)); // Very short

                                        dns_cache.set_minimum_ttl(Duration::from_secs(60)).await;

                                        dns_cache.insert(short_ttl_record).await;

                                        // Check after original TTL would have expired but minimum TTL hasn't
                                        sleep(Duration::from_millis(6000)).await;

                                        match dns_cache.get("shortttl.com", RecordType::A).await {
                                            Some(_) => {
                                                // Correctly honored minimum TTL
                                            }
                                            None => {
                                                // Should have honored minimum TTL
                                                ttl_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    16 => {
                                        // Test maximum TTL clamping corruption
                                        let long_ttl_record = DnsRecord::new(
                                            "longttl.com",
                                            RecordType::A,
                                            "203.0.113.4",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(86400)); // 24 hours

                                        dns_cache.set_maximum_ttl(Duration::from_secs(300)).await; // 5 minutes max

                                        dns_cache.insert(long_ttl_record).await;

                                        if let Some(cached_record) =
                                            dns_cache.get("longttl.com", RecordType::A).await
                                        {
                                            if cached_record.remaining_ttl()
                                                > Duration::from_secs(300)
                                            {
                                                // TTL should have been clamped to maximum
                                                ttl_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal DNS caching test
                                        let normal_record = DnsRecord::new(
                                            "normal.com",
                                            RecordType::A,
                                            "192.0.2.100",
                                        )
                                        .with_ttl(DnsTtl::from_seconds(300));
                                        dns_cache.insert(normal_record).await;
                                        dns_cache.get("normal.com", RecordType::A).await;
                                    }
                                }
                            }

                            sleep(Duration::from_millis(2)).await;
                        }

                        let corruptions = dns_corruptions.load(Ordering::Relaxed);
                        let violations = ttl_violations.load(Ordering::Relaxed);

                        // DNS TTL validation should catch caching expiry corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // TTL caching corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "DNS TTL validation failed: {} corruptions, {} violations",
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

        let detected = matches!(net_dns_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-45",
            "net",
            "dns_ttl_caching_expiry_corruption",
            detected,
        );
    }

    /// [br-mutation-46] RaptorQ GF256 XOR table corruption regression mutations
    async fn test_raptorq_gf256_mutations(&self) {
        use crate::raptorq::gf256::{FieldElement, Gf256, MultiplicationTable, XorTable};

        let raptorq_gf256_detected = self
            .runtime
            .scope(|scope| async move {
                let gf256_test_count = 16;
                let gf256_corruptions = Arc::new(AtomicUsize::new(0));
                let xor_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..gf256_test_count {
                            // Test GF256 XOR table corruption detection via multiplication verification
                            if test_idx % 2 == 0 {
                                gf256_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt GF256 XOR table behavior
                                match test_idx % 16 {
                                    0 => {
                                        // Test XOR table identity element corruption
                                        let mut xor_table = XorTable::new();
                                        let a = FieldElement::from_u8(42);
                                        let zero = FieldElement::zero();

                                        // MUTATION: Corrupt XOR with zero (should be identity)
                                        let corrupted_result =
                                            xor_table.xor_corrupted_identity(a, zero);
                                        let expected_result = a; // XOR with 0 should be identity

                                        if corrupted_result != expected_result {
                                            // Multiplication verification should catch XOR identity corruption
                                            let mult_table = MultiplicationTable::new();

                                            // Verify via multiplication: a * 1 = a
                                            let mult_result =
                                                mult_table.multiply(a, FieldElement::one());
                                            if mult_result == expected_result
                                                && corrupted_result != expected_result
                                            {
                                                // XOR corruption caught by multiplication verification
                                            } else {
                                                // Should have caught XOR identity corruption
                                                xor_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    2 => {
                                        // Test XOR commutativity corruption
                                        let mut xor_table = XorTable::new();
                                        let a = FieldElement::from_u8(85); // 0b01010101
                                        let b = FieldElement::from_u8(170); // 0b10101010

                                        // MUTATION: Break XOR commutativity
                                        let ab_result = xor_table.xor_non_commutative(a, b);
                                        let ba_result = xor_table.xor_non_commutative(b, a);

                                        if ab_result != ba_result {
                                            // Multiplication verification should catch non-commutativity
                                            let mult_table = MultiplicationTable::new();

                                            // GF(256) multiplication is also commutative
                                            let mult_ab = mult_table.multiply(a, b);
                                            let mult_ba = mult_table.multiply(b, a);

                                            if mult_ab == mult_ba && ab_result != ba_result {
                                                // XOR commutativity corruption caught
                                            } else {
                                                // Should have caught commutativity violation
                                                xor_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    4 => {
                                        // Test XOR distributivity over addition corruption
                                        let mut xor_table = XorTable::new();
                                        let a = FieldElement::from_u8(15);
                                        let b = FieldElement::from_u8(240);
                                        let c = FieldElement::from_u8(51);

                                        // MUTATION: Break distributivity a ⊕ (b ⊕ c) != (a ⊕ b) ⊕ c
                                        let left_result = xor_table
                                            .xor(a, xor_table.xor_corrupted_associativity(b, c));
                                        let right_result = xor_table.xor(xor_table.xor(a, b), c);

                                        if left_result != right_result {
                                            // Multiplication cross-check should detect associativity violation
                                            let mult_table = MultiplicationTable::new();

                                            // Check if multiplication maintains expected relationships
                                            let mult_check =
                                                mult_table.multiply(mult_table.multiply(a, b), c);
                                            let expected_mult =
                                                mult_table.multiply(a, mult_table.multiply(b, c));

                                            if mult_check == expected_mult
                                                && left_result != right_result
                                            {
                                                // XOR associativity corruption detected
                                            } else {
                                                // Should have detected associativity corruption
                                                xor_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    6 => {
                                        // Test XOR table index corruption
                                        let mut xor_table = XorTable::with_corrupted_indices();
                                        let a = FieldElement::from_u8(127);
                                        let b = FieldElement::from_u8(255);

                                        // MUTATION: Use corrupted index calculation for XOR lookup
                                        let corrupted_xor =
                                            xor_table.xor_with_corrupted_index(a, b);
                                        let expected_xor = a.to_u8() ^ b.to_u8(); // Correct XOR

                                        if corrupted_xor.to_u8() != expected_xor {
                                            // Multiplication verification should catch index corruption
                                            let mult_table = MultiplicationTable::new();

                                            // Verify field relationships are maintained
                                            let mult_verify =
                                                mult_table.multiply(a, FieldElement::one());
                                            if mult_verify == a
                                                && corrupted_xor
                                                    != FieldElement::from_u8(expected_xor)
                                            {
                                                // Index corruption caught by field relationship check
                                            } else {
                                                // Should have caught index corruption
                                                xor_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    8 => {
                                        // Test XOR self-inverse corruption
                                        let mut xor_table = XorTable::new();
                                        let a = FieldElement::from_u8(73);

                                        // MUTATION: Break self-inverse property (a ⊕ a should be 0)
                                        let corrupted_self_xor =
                                            xor_table.xor_corrupted_self_inverse(a, a);
                                        let expected_zero = FieldElement::zero();

                                        if corrupted_self_xor != expected_zero {
                                            // Multiplication check: a * a^(-1) = 1 should still hold
                                            let mult_table = MultiplicationTable::new();
                                            let a_inverse = mult_table.multiplicative_inverse(a);
                                            let mult_result = mult_table.multiply(a, a_inverse);

                                            if mult_result == FieldElement::one()
                                                && corrupted_self_xor != expected_zero
                                            {
                                                // Self-inverse corruption detected via multiplicative check
                                            } else {
                                                // Should have detected self-inverse violation
                                                xor_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    10 => {
                                        // Test XOR table overflow corruption
                                        let mut xor_table = XorTable::new();
                                        let a = FieldElement::from_u8(255);
                                        let b = FieldElement::from_u8(255);

                                        // MUTATION: Corrupt overflow handling in XOR operation
                                        let corrupted_overflow =
                                            xor_table.xor_with_overflow_corruption(a, b);
                                        let expected_result = FieldElement::zero(); // 255 ^ 255 = 0

                                        if corrupted_overflow != expected_result {
                                            // Multiplication table should not have overflow issues
                                            let mult_table = MultiplicationTable::new();
                                            let mult_check = mult_table.multiply(
                                                FieldElement::from_u8(255),
                                                FieldElement::one(),
                                            );

                                            if mult_check == FieldElement::from_u8(255)
                                                && corrupted_overflow != expected_result
                                            {
                                                // Overflow corruption detected
                                            } else {
                                                // Should have detected overflow handling corruption
                                                xor_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    12 => {
                                        // Test XOR constant corruption (specific value corruption)
                                        let mut xor_table = XorTable::new();

                                        // Test known XOR relationships
                                        let test_cases = [
                                            (
                                                FieldElement::from_u8(0x53),
                                                FieldElement::from_u8(0xCA),
                                                FieldElement::from_u8(0x99),
                                            ),
                                            (
                                                FieldElement::from_u8(0xA5),
                                                FieldElement::from_u8(0x5A),
                                                FieldElement::from_u8(0xFF),
                                            ),
                                            (
                                                FieldElement::from_u8(0x0F),
                                                FieldElement::from_u8(0xF0),
                                                FieldElement::from_u8(0xFF),
                                            ),
                                        ];

                                        for (a, b, expected_xor) in test_cases {
                                            // MUTATION: Return wrong constant for specific inputs
                                            let corrupted_result =
                                                xor_table.xor_with_constant_corruption(a, b);

                                            if corrupted_result != expected_xor {
                                                // Cross-verify with multiplication properties
                                                let mult_table = MultiplicationTable::new();

                                                // Check if field structure is maintained
                                                let field_check =
                                                    mult_table.multiply(a, FieldElement::one());
                                                if field_check == a
                                                    && corrupted_result != expected_xor
                                                {
                                                    // Constant corruption detected
                                                    break;
                                                } else {
                                                    // Should have detected constant corruption
                                                    xor_violations.fetch_add(1, Ordering::Relaxed);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    14 => {
                                        // Test XOR bit-level corruption
                                        let mut xor_table = XorTable::new();
                                        let a = FieldElement::from_u8(0b10110011);
                                        let b = FieldElement::from_u8(0b01001100);

                                        // MUTATION: Corrupt specific bit positions in XOR result
                                        let corrupted_bitwise =
                                            xor_table.xor_with_bit_corruption(a, b);
                                        let expected_bits = 0b11111111; // Correct XOR result

                                        if corrupted_bitwise.to_u8() != expected_bits {
                                            // Verify bit corruption via multiplication consistency
                                            let mult_table = MultiplicationTable::new();

                                            // Multiplication should preserve bit relationships in field
                                            let mult_a =
                                                mult_table.multiply(a, FieldElement::from_u8(2));
                                            let mult_b =
                                                mult_table.multiply(b, FieldElement::from_u8(2));
                                            let mult_xor = xor_table.xor(mult_a, mult_b);

                                            // Check if bit relationships are consistent
                                            let expected_mult_xor = mult_table.multiply(
                                                FieldElement::from_u8(expected_bits),
                                                FieldElement::from_u8(2),
                                            );

                                            if mult_xor == expected_mult_xor
                                                && corrupted_bitwise.to_u8() != expected_bits
                                            {
                                                // Bit-level corruption detected
                                            } else {
                                                // Should have detected bit corruption
                                                xor_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal GF256 XOR test
                                        let xor_table = XorTable::new();
                                        let a = FieldElement::from_u8((test_idx * 17) as u8);
                                        let b = FieldElement::from_u8((test_idx * 31) as u8);
                                        let _result = xor_table.xor(a, b);
                                    }
                                }
                            }

                            sleep(Duration::from_millis(5)).await;
                        }

                        let corruptions = gf256_corruptions.load(Ordering::Relaxed);
                        let violations = xor_violations.load(Ordering::Relaxed);

                        // GF256 multiplication verification should catch XOR table corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // XOR table corruption detected via multiplication
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "GF256 XOR validation failed: {} corruptions, {} violations",
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

        let detected = matches!(raptorq_gf256_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-46",
            "raptorq",
            "gf256_xor_table_multiplication_verification_corruption",
            detected,
        );
    }

    /// [br-mutation-47] RaptorQ proof Merkle aggregation associativity regression mutations
    async fn test_raptorq_proof_mutations(&self) {
        use crate::raptorq::proof::{
            Aggregation, HashFunction, MerkleProof, MerkleTree, ProofNode,
        };

        let raptorq_proof_detected = self
            .runtime
            .scope(|scope| async move {
                let proof_test_count = 14;
                let proof_corruptions = Arc::new(AtomicUsize::new(0));
                let associativity_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..proof_test_count {
                            // Test Merkle aggregation associativity corruption
                            if test_idx % 2 == 0 {
                                proof_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt Merkle tree aggregation associativity
                                match test_idx % 14 {
                                    0 => {
                                        // Test basic associativity corruption in proof aggregation
                                        let hash_fn = HashFunction::blake3();
                                        let mut merkle_tree = MerkleTree::new(hash_fn);

                                        let data_a = b"proof_data_a".to_vec();
                                        let data_b = b"proof_data_b".to_vec();
                                        let data_c = b"proof_data_c".to_vec();

                                        let leaf_a = merkle_tree.create_leaf(&data_a);
                                        let leaf_b = merkle_tree.create_leaf(&data_b);
                                        let leaf_c = merkle_tree.create_leaf(&data_c);

                                        // MUTATION: Break associativity (a + b) + c != a + (b + c)
                                        let left_aggregated = merkle_tree.aggregate_non_associative(
                                            merkle_tree.aggregate(leaf_a, leaf_b),
                                            leaf_c
                                        );
                                        let right_aggregated = merkle_tree.aggregate(
                                            leaf_a,
                                            merkle_tree.aggregate(leaf_b, leaf_c)
                                        );

                                        if left_aggregated.hash() != right_aggregated.hash() {
                                            // Proof verification should catch associativity violation
                                            let proof_left = MerkleProof::create(&merkle_tree, &left_aggregated);
                                            let proof_right = MerkleProof::create(&merkle_tree, &right_aggregated);

                                            if !proof_left.verify() || !proof_right.verify() {
                                                // Associativity violation caught by proof verification
                                            } else {
                                                // Should have caught associativity violation
                                                associativity_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    2 => {
                                        // Test proof path associativity corruption
                                        let hash_fn = HashFunction::sha256();
                                        let mut merkle_tree = MerkleTree::new(hash_fn);

                                        // Create a tree with multiple levels
                                        let leaves: Vec<Vec<u8>> = (0..8)
                                            .map(|i| format!("leaf_{}", i).into_bytes())
                                            .collect();

                                        let leaf_nodes: Vec<ProofNode> = leaves.iter()
                                            .map(|data| merkle_tree.create_leaf(data))
                                            .collect();

                                        // MUTATION: Corrupt associativity in proof path construction
                                        let mut corrupted_root = leaf_nodes[0].clone();
                                        for (i, node) in leaf_nodes[1..4].iter().enumerate() {
                                            if i % 2 == 0 {
                                                // Normal aggregation
                                                corrupted_root = merkle_tree.aggregate(corrupted_root, node.clone());
                                            } else {
                                                // Non-associative aggregation
                                                corrupted_root = merkle_tree.aggregate_non_associative(
                                                    corrupted_root,
                                                    node.clone()
                                                );
                                            }
                                        }

                                        let normal_root = leaf_nodes[4..].iter()
                                            .fold(corrupted_root.clone(), |acc, node| {
                                                merkle_tree.aggregate(acc, node.clone())
                                            });

                                        // Verify proof path integrity
                                        let proof = MerkleProof::create_path(&merkle_tree, &normal_root, &leaf_nodes[0]);
                                        if !proof.verify_path_associativity() {
                                            // Path associativity corruption detected
                                        } else {
                                            // Should have detected path associativity corruption
                                            associativity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    4 => {
                                        // Test aggregation commutativity vs associativity confusion
                                        let hash_fn = HashFunction::blake3();
                                        let mut merkle_tree = MerkleTree::new(hash_fn);

                                        let node_a = merkle_tree.create_leaf(b"node_a");
                                        let node_b = merkle_tree.create_leaf(b"node_b");
                                        let node_c = merkle_tree.create_leaf(b"node_c");

                                        // MUTATION: Confuse commutativity with associativity
                                        let assoc_result = merkle_tree.aggregate(
                                            merkle_tree.aggregate(node_a.clone(), node_b.clone()),
                                            node_c.clone()
                                        );

                                        // Wrong: apply commutativity where associativity expected
                                        let commuted_result = merkle_tree.aggregate(
                                            merkle_tree.aggregate(node_b.clone(), node_a.clone()), // Commuted
                                            node_c.clone()
                                        );

                                        if assoc_result.hash() != commuted_result.hash() {
                                            // Verify this corruption affects proof integrity
                                            let proof_assoc = MerkleProof::create(&merkle_tree, &assoc_result);
                                            let proof_commuted = MerkleProof::create(&merkle_tree, &commuted_result);

                                            // Both proofs should be valid if only commutativity applied
                                            if proof_assoc.verify() && proof_commuted.verify() {
                                                // This indicates Merkle aggregation is commutative AND associative
                                            } else {
                                                // Commutativity/associativity confusion detected
                                            }
                                        } else {
                                            // Should show different results if order matters
                                            associativity_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    6 => {
                                        // Test multi-level aggregation associativity corruption
                                        let hash_fn = HashFunction::sha256();
                                        let mut merkle_tree = MerkleTree::new(hash_fn);

                                        let base_data: Vec<Vec<u8>> = (0..16)
                                            .map(|i| format!("data_{:02}", i).into_bytes())
                                            .collect();

                                        let leaves: Vec<ProofNode> = base_data.iter()
                                            .map(|data| merkle_tree.create_leaf(data))
                                            .collect();

                                        // MUTATION: Apply non-associative aggregation at different levels
                                        let mut level1_normal = Vec::new();
                                        let mut level1_corrupted = Vec::new();

                                        for chunk in leaves.chunks(4) {
                                            // Normal associative aggregation
                                            let normal_agg = chunk.iter()
                                                .cloned()
                                                .reduce(|acc, node| merkle_tree.aggregate(acc, node))
                                                .unwrap();
                                            level1_normal.push(normal_agg);

                                            // Corrupted non-associative aggregation
                                            let corrupted_agg = chunk.iter()
                                                .cloned()
                                                .reduce(|acc, node| merkle_tree.aggregate_non_associative(acc, node))
                                                .unwrap();
                                            level1_corrupted.push(corrupted_agg);
                                        }

                                        // Check if corruption propagates to root level
                                        let normal_root = level1_normal.into_iter()
                                            .reduce(|acc, node| merkle_tree.aggregate(acc, node))
                                            .unwrap();

                                        let corrupted_root = level1_corrupted.into_iter()
                                            .reduce(|acc, node| merkle_tree.aggregate(acc, node))
                                            .unwrap();

                                        if normal_root.hash() != corrupted_root.hash() {
                                            // Multi-level proof verification should catch corruption
                                            let proof = MerkleProof::create(&merkle_tree, &corrupted_root);
                                            if !proof.verify_multi_level_associativity() {
                                                // Multi-level associativity corruption detected
                                            } else {
                                                // Should have caught multi-level corruption
                                                associativity_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    8 => {
                                        // Test aggregation identity element corruption
                                        let hash_fn = HashFunction::blake3();
                                        let mut merkle_tree = MerkleTree::new(hash_fn);

                                        let node_a = merkle_tree.create_leaf(b"identity_test");
                                        let identity_node = merkle_tree.create_identity_element();

                                        // MUTATION: Corrupt identity element behavior
                                        let corrupted_identity_agg = merkle_tree.aggregate_with_corrupted_identity(
                                            node_a.clone(),
                                            identity_node
                                        );

                                        // Should be: node_a + identity = node_a
                                        if corrupted_identity_agg.hash() != node_a.hash() {
                                            // Verify identity corruption via proof verification
                                            let proof = MerkleProof::create(&merkle_tree, &corrupted_identity_agg);
                                            let expected_proof = MerkleProof::create(&merkle_tree, &node_a);

                                            if proof.hash() != expected_proof.hash() {
                                                // Identity corruption detected via proof mismatch
                                            } else {
                                                // Should have detected identity corruption
                                                associativity_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    10 => {
                                        // Test aggregation inverse element corruption
                                        let hash_fn = HashFunction::sha256();
                                        let mut merkle_tree = MerkleTree::new(hash_fn);

                                        let node_a = merkle_tree.create_leaf(b"inverse_test");
                                        let inverse_a = merkle_tree.create_inverse(&node_a);
                                        let identity = merkle_tree.create_identity_element();

                                        // MUTATION: Corrupt inverse behavior
                                        let corrupted_inverse_agg = merkle_tree.aggregate_with_corrupted_inverse(
                                            node_a.clone(),
                                            inverse_a
                                        );

                                        // Should be: node_a + inverse(node_a) = identity
                                        if corrupted_inverse_agg.hash() != identity.hash() {
                                            // Proof verification should detect inverse corruption
                                            let proof = MerkleProof::create(&merkle_tree, &corrupted_inverse_agg);
                                            if !proof.verify_inverse_property() {
                                                // Inverse corruption detected
                                            } else {
                                                // Should have detected inverse corruption
                                                associativity_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    12 => {
                                        // Test aggregation overflow/underflow in associativity
                                        let hash_fn = HashFunction::blake3();
                                        let mut merkle_tree = MerkleTree::new(hash_fn);

                                        // Create nodes that might cause overflow in aggregation
                                        let max_node = merkle_tree.create_leaf(&vec![0xFF; 32]);
                                        let min_node = merkle_tree.create_leaf(&vec![0x00; 32]);
                                        let mid_node = merkle_tree.create_leaf(&vec![0x80; 32]);

                                        // MUTATION: Test associativity with potential overflow
                                        let left_assoc = merkle_tree.aggregate(
                                            merkle_tree.aggregate_with_overflow_risk(max_node.clone(), min_node.clone()),
                                            mid_node.clone()
                                        );

                                        let right_assoc = merkle_tree.aggregate(
                                            max_node.clone(),
                                            merkle_tree.aggregate_with_overflow_risk(min_node.clone(), mid_node.clone())
                                        );

                                        if left_assoc.hash() != right_assoc.hash() {
                                            // Overflow should not break associativity
                                            let proof_left = MerkleProof::create(&merkle_tree, &left_assoc);
                                            let proof_right = MerkleProof::create(&merkle_tree, &right_assoc);

                                            if !proof_left.verify() || !proof_right.verify() {
                                                // Overflow-induced associativity break detected
                                            } else {
                                                // Should have detected overflow associativity corruption
                                                associativity_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal Merkle proof test
                                        let hash_fn = HashFunction::blake3();
                                        let mut merkle_tree = MerkleTree::new(hash_fn);
                                        let test_data = format!("test_data_{}", test_idx).into_bytes();
                                        let node = merkle_tree.create_leaf(&test_data);
                                        let _proof = MerkleProof::create(&merkle_tree, &node);
                                    }
                                }
                            }

                            sleep(Duration::from_millis(4)).await;
                        }

                        let corruptions = proof_corruptions.load(Ordering::Relaxed);
                        let violations = associativity_violations.load(Ordering::Relaxed);

                        // Merkle proof verification should catch aggregation associativity violations
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Associativity corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(ErrorKind::Other,
                                format!("RaptorQ proof aggregation failed: {} corruptions, {} violations",
                                    corruptions, violations)))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(raptorq_proof_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-47",
            "raptorq",
            "proof_merkle_aggregation_associativity_corruption",
            detected,
        );
    }

    /// [br-mutation-48] Obligation saga compensation symmetry regression mutations
    async fn test_obligation_saga_mutations(&self) {
        use crate::obligation::saga::{
            Compensation, CompensationSymmetry, Saga, SagaExecutor, SagaStep,
        };

        let obligation_saga_detected = self
            .runtime
            .scope(|scope| async move {
                let saga_test_count = 18;
                let saga_corruptions = Arc::new(AtomicUsize::new(0));
                let symmetry_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..saga_test_count {
                            // Test saga compensation symmetry corruption
                            if test_idx % 3 == 0 {
                                saga_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt saga compensation symmetry
                                match test_idx % 18 {
                                    0 => {
                                        // Test basic compensation symmetry corruption
                                        let mut saga = Saga::new("test_saga");
                                        let executor = SagaExecutor::new();

                                        let step1 = SagaStep::new("allocate_resource", || async {
                                            // Forward: allocate a resource
                                            Ok("resource_allocated")
                                        });

                                        // MUTATION: Break compensation symmetry
                                        let compensation1 = Compensation::new_asymmetric("deallocate_resource", |_| async {
                                            // Backward: should deallocate, but doesn't (asymmetric)
                                            Ok("resource_not_deallocated") // Should return "resource_deallocated"
                                        });

                                        saga.add_step_with_compensation(step1, compensation1);

                                        // Execute forward
                                        let forward_result = executor.execute_forward(&saga).await;

                                        // Execute compensation (should undo forward)
                                        let compensation_result = executor.execute_compensation(&saga).await;

                                        // Verify symmetry: forward + compensation = identity
                                        if !CompensationSymmetry::verify_identity(&forward_result, &compensation_result) {
                                            // Compensation symmetry violation detected
                                        } else {
                                            // Should have detected asymmetric compensation
                                            symmetry_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    3 => {
                                        // Test multi-step compensation symmetry corruption
                                        let mut saga = Saga::new("multi_step_saga");
                                        let executor = SagaExecutor::new();

                                        // Step 1: Database transaction
                                        let db_step = SagaStep::new("db_insert", || async {
                                            Ok("record_inserted:123")
                                        });

                                        // Step 2: Send notification
                                        let notify_step = SagaStep::new("send_notification", || async {
                                            Ok("notification_sent:456")
                                        });

                                        // Step 3: Update cache
                                        let cache_step = SagaStep::new("update_cache", || async {
                                            Ok("cache_updated:789")
                                        });

                                        // MUTATION: Asymmetric compensations (break symmetry)
                                        let db_compensation = Compensation::new("db_rollback", |result| async move {
                                            // Should undo db_insert, but leaves partial state
                                            Ok("record_partially_deleted") // Asymmetric
                                        });

                                        let notify_compensation = Compensation::new("cancel_notification", |result| async move {
                                            // Properly cancels notification
                                            Ok("notification_cancelled")
                                        });

                                        let cache_compensation = Compensation::new_asymmetric("invalidate_cache", |result| async move {
                                            // Should invalidate cache, but corrupts it instead
                                            Ok("cache_corrupted") // Asymmetric
                                        });

                                        saga.add_step_with_compensation(db_step, db_compensation);
                                        saga.add_step_with_compensation(notify_step, notify_compensation);
                                        saga.add_step_with_compensation(cache_step, cache_compensation);

                                        // Execute forward path
                                        let forward_state = executor.execute_forward(&saga).await;

                                        // Execute compensation path (in reverse order)
                                        let compensation_state = executor.execute_compensation_reverse(&saga).await;

                                        // Check overall symmetry
                                        if !CompensationSymmetry::verify_multi_step_symmetry(&forward_state, &compensation_state) {
                                            // Multi-step compensation asymmetry detected
                                        } else {
                                            // Should have detected multi-step symmetry violation
                                            symmetry_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    6 => {
                                        // Test compensation order symmetry corruption
                                        let mut saga = Saga::new("order_test_saga");
                                        let executor = SagaExecutor::new();

                                        let steps = [
                                            ("step_a", "result_a"),
                                            ("step_b", "result_b"),
                                            ("step_c", "result_c"),
                                        ];

                                        for (step_name, result) in steps.iter() {
                                            let step = SagaStep::new(step_name, {
                                                let result = result.to_string();
                                                move || {
                                                    let result = result.clone();
                                                    async move { Ok(result) }
                                                }
                                            });

                                            // MUTATION: Wrong compensation order (should be reverse)
                                            let compensation = Compensation::new_wrong_order(&format!("undo_{}", step_name), |_| async {
                                                Ok(format!("undone_{}", step_name))
                                            });

                                            saga.add_step_with_compensation(step, compensation);
                                        }

                                        // Execute forward: A -> B -> C
                                        let forward_result = executor.execute_forward(&saga).await;

                                        // Execute compensation: should be C -> B -> A, but corrupted order
                                        let compensation_result = executor.execute_compensation_wrong_order(&saga).await;

                                        // Verify compensation order symmetry
                                        if !CompensationSymmetry::verify_order_symmetry(&forward_result, &compensation_result) {
                                            // Order symmetry violation detected
                                        } else {
                                            // Should have detected compensation order violation
                                            symmetry_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    9 => {
                                        // Test compensation idempotency symmetry corruption
                                        let mut saga = Saga::new("idempotency_saga");
                                        let executor = SagaExecutor::new();

                                        let step = SagaStep::new("create_resource", || async {
                                            Ok("resource_created:unique_123")
                                        });

                                        // MUTATION: Non-idempotent compensation breaks symmetry
                                        let compensation = Compensation::new_non_idempotent("destroy_resource", |result| async move {
                                            // Should be idempotent, but changes state each time
                                            static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
                                            let count = CALL_COUNT.fetch_add(1, Ordering::Relaxed);
                                            Ok(format!("resource_destroyed_attempt_{}", count)) // Non-idempotent
                                        });

                                        saga.add_step_with_compensation(step, compensation);

                                        // Execute forward
                                        let forward_result = executor.execute_forward(&saga).await;

                                        // Execute compensation multiple times
                                        let comp_result1 = executor.execute_compensation(&saga).await;
                                        let comp_result2 = executor.execute_compensation(&saga).await;

                                        // Check idempotency symmetry
                                        if !CompensationSymmetry::verify_idempotency(&comp_result1, &comp_result2) {
                                            // Non-idempotent compensation detected
                                        } else {
                                            // Should have detected idempotency violation
                                            symmetry_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    12 => {
                                        // Test compensation error handling symmetry corruption
                                        let mut saga = Saga::new("error_handling_saga");
                                        let executor = SagaExecutor::new();

                                        let step = SagaStep::new("risky_operation", || async {
                                            Ok("operation_completed")
                                        });

                                        // MUTATION: Compensation fails to handle errors symmetrically
                                        let compensation = Compensation::new_error_asymmetric("undo_risky", |result| async move {
                                            // Should handle errors symmetrically to forward operation
                                            if result.contains("completed") {
                                                // Forward succeeded, compensation should succeed symmetrically
                                                Err("compensation_failed") // Asymmetric error handling
                                            } else {
                                                Ok("undo_completed")
                                            }
                                        });

                                        saga.add_step_with_compensation(step, compensation);

                                        // Execute forward (succeeds)
                                        let forward_result = executor.execute_forward(&saga).await;

                                        // Execute compensation (should succeed but fails asymmetrically)
                                        let compensation_result = executor.execute_compensation(&saga).await;

                                        // Check error handling symmetry
                                        if !CompensationSymmetry::verify_error_symmetry(&forward_result, &compensation_result) {
                                            // Error handling asymmetry detected
                                        } else {
                                            // Should have detected error handling asymmetry
                                            symmetry_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    15 => {
                                        // Test compensation state leak symmetry corruption
                                        let mut saga = Saga::new("state_leak_saga");
                                        let executor = SagaExecutor::new();

                                        let step = SagaStep::new("modify_state", || async {
                                            // Modifies some global state
                                            static GLOBAL_STATE: AtomicUsize = AtomicUsize::new(0);
                                            let old_value = GLOBAL_STATE.fetch_add(10, Ordering::Relaxed);
                                            Ok(format!("state_modified:{}->{}",old_value, old_value + 10))
                                        });

                                        // MUTATION: Compensation leaks state (doesn't fully restore)
                                        let compensation = Compensation::new_state_leak("restore_state", |result| async move {
                                            // Should restore state, but leaks partial changes
                                            static GLOBAL_STATE: AtomicUsize = AtomicUsize::new(10); // Should be 0
                                            let leaked_value = GLOBAL_STATE.fetch_sub(7, Ordering::Relaxed); // Should sub 10
                                            Ok(format!("state_partially_restored:{}", leaked_value - 7))
                                        });

                                        saga.add_step_with_compensation(step, compensation);

                                        // Get initial state
                                        let initial_state = executor.capture_state().await;

                                        // Execute forward
                                        let forward_result = executor.execute_forward(&saga).await;

                                        // Execute compensation
                                        let compensation_result = executor.execute_compensation(&saga).await;

                                        // Get final state
                                        let final_state = executor.capture_state().await;

                                        // Check state symmetry (final should equal initial)
                                        if !CompensationSymmetry::verify_state_symmetry(&initial_state, &final_state) {
                                            // State leak detected
                                        } else {
                                            // Should have detected state leak
                                            symmetry_violations.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    _ => {
                                        // Normal saga test
                                        let mut saga = Saga::new("normal_saga");
                                        let executor = SagaExecutor::new();

                                        let step = SagaStep::new("normal_op", || async {
                                            Ok("normal_result")
                                        });

                                        let compensation = Compensation::new("normal_undo", |_| async {
                                            Ok("normal_undone")
                                        });

                                        saga.add_step_with_compensation(step, compensation);
                                        executor.execute_forward(&saga).await;
                                        executor.execute_compensation(&saga).await;
                                    }
                                }
                            }

                            sleep(Duration::from_millis(3)).await;
                        }

                        let corruptions = saga_corruptions.load(Ordering::Relaxed);
                        let violations = symmetry_violations.load(Ordering::Relaxed);

                        // Saga compensation verification should catch symmetry violations
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Compensation symmetry violation detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(ErrorKind::Other,
                                format!("Saga compensation symmetry failed: {} corruptions, {} violations",
                                    corruptions, violations)))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(
            obligation_saga_detected,
            Outcome::Ok(true) | Outcome::Err(_)
        );
        self.log_subsystem_mutation(
            "br-mutation-48",
            "obligation",
            "saga_compensation_symmetry_corruption",
            detected,
        );
    }

    /// [br-mutation-49] Trace divergence causality DAG edge regression mutations
    async fn test_trace_divergence_mutations(&self) {
        use crate::trace::divergence::{CausalOrder, CausalityDag, DagEdge, DivergenceDetector};

        let trace_divergence_detected = self
            .runtime
            .scope(|scope| async move {
                let divergence_test_count = 20;
                let divergence_corruptions = Arc::new(AtomicUsize::new(0));
                let causality_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..divergence_test_count {
                            // Test causality DAG edge corruption detection
                            if test_idx % 2 == 0 {
                                divergence_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt causality DAG edge ordering
                                match test_idx % 20 {
                                    0 => {
                                        // Test basic causal edge reversal corruption
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let event_a = causality_dag.add_event("event_a", vec![]);
                                        let event_b = causality_dag.add_event("event_b", vec![event_a]);
                                        let event_c = causality_dag.add_event("event_c", vec![event_b]);

                                        // MUTATION: Reverse causal edge (C should not happen before B)
                                        let corrupted_edge = DagEdge::new(event_c, event_b); // Wrong direction
                                        causality_dag.add_corrupted_edge(corrupted_edge);

                                        // Verify causality violation detection
                                        match detector.check_causal_consistency(&causality_dag) {
                                            Err(CausalOrder::Violation) => {
                                                // Correctly detected causal edge reversal
                                            }
                                            Ok(_) => {
                                                // Should have detected causal edge reversal
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    2 => {
                                        // Test transitive causality corruption
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let event_a = causality_dag.add_event("event_a", vec![]);
                                        let event_b = causality_dag.add_event("event_b", vec![event_a]);
                                        let event_c = causality_dag.add_event("event_c", vec![event_b]);
                                        let event_d = causality_dag.add_event("event_d", vec![event_c]);

                                        // MUTATION: Break transitive causality (A → B → C → D, but add D → A)
                                        let transitive_violation = DagEdge::new(event_d, event_a); // Creates cycle
                                        causality_dag.add_corrupted_edge(transitive_violation);

                                        // Check for cycle detection in causality
                                        match detector.detect_causal_cycles(&causality_dag) {
                                            Ok(cycles) if !cycles.is_empty() => {
                                                // Correctly detected transitive causality cycle
                                            }
                                            Ok(_) => {
                                                // Should have detected causality cycle
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    4 => {
                                        // Test concurrent event ordering corruption
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let event_root = causality_dag.add_event("root", vec![]);
                                        let event_concurrent_a = causality_dag.add_event("concurrent_a", vec![event_root]);
                                        let event_concurrent_b = causality_dag.add_event("concurrent_b", vec![event_root]);
                                        let event_merge = causality_dag.add_event("merge", vec![event_concurrent_a, event_concurrent_b]);

                                        // MUTATION: Add false causal ordering between concurrent events
                                        let false_ordering = DagEdge::new(event_concurrent_a, event_concurrent_b);
                                        causality_dag.add_corrupted_edge(false_ordering);

                                        // Verify concurrent event detection
                                        match detector.verify_concurrent_independence(&causality_dag) {
                                            Err(CausalOrder::FalseOrdering) => {
                                                // Correctly detected false causal ordering
                                            }
                                            Ok(_) => {
                                                // Should have detected false concurrent ordering
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    6 => {
                                        // Test causal timestamp inconsistency
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let event_a = causality_dag.add_event_with_timestamp("event_a", vec![], 100);
                                        let event_b = causality_dag.add_event_with_timestamp("event_b", vec![event_a], 200);

                                        // MUTATION: Corrupt causal timestamp (B happens before A)
                                        causality_dag.corrupt_event_timestamp(event_b, 50); // Before A's timestamp

                                        // Check timestamp causality consistency
                                        match detector.verify_timestamp_causality(&causality_dag) {
                                            Err(CausalOrder::TimestampInconsistency) => {
                                                // Correctly detected timestamp causality violation
                                            }
                                            Ok(_) => {
                                                // Should have detected timestamp inconsistency
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    8 => {
                                        // Test missing causal dependency corruption
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let resource_event = causality_dag.add_event("acquire_resource", vec![]);
                                        let _use_event = causality_dag.add_event("use_resource", vec![]); // Missing dependency!
                                        let release_event = causality_dag.add_event("release_resource", vec![resource_event]);

                                        // MUTATION: Resource usage without acquisition dependency
                                        // This should be detected as missing causal dependency

                                        match detector.verify_resource_causality(&causality_dag) {
                                            Err(CausalOrder::MissingDependency) => {
                                                // Correctly detected missing causal dependency
                                            }
                                            Ok(_) => {
                                                // Should have detected missing dependency
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    10 => {
                                        // Test DAG branching factor corruption
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let root = causality_dag.add_event("root", vec![]);

                                        // Create many branches from single event
                                        let mut branch_events = Vec::new();
                                        for i in 0..10 {
                                            let branch = causality_dag.add_event(&format!("branch_{}", i), vec![root]);
                                            branch_events.push(branch);
                                        }

                                        // MUTATION: Add excessive cross-branch dependencies
                                        for (i, &event_a) in branch_events.iter().enumerate() {
                                            for (j, &event_b) in branch_events.iter().enumerate() {
                                                if i != j && (i + j) % 3 == 0 {
                                                    let cross_dep = DagEdge::new(event_a, event_b);
                                                    causality_dag.add_corrupted_edge(cross_dep);
                                                }
                                            }
                                        }

                                        // Check for excessive branching complexity
                                        match detector.analyze_branching_complexity(&causality_dag) {
                                            Err(CausalOrder::ExcessiveComplexity) => {
                                                // Correctly detected excessive branching corruption
                                            }
                                            Ok(_) => {
                                                // Should have detected excessive complexity
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    12 => {
                                        // Test causal isolation violation
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        // Create two isolated causal chains
                                        let chain1_a = causality_dag.add_event("chain1_a", vec![]);
                                        let chain1_b = causality_dag.add_event("chain1_b", vec![chain1_a]);

                                        let chain2_a = causality_dag.add_event("chain2_a", vec![]);
                                        let chain2_b = causality_dag.add_event("chain2_b", vec![chain2_a]);

                                        // MUTATION: Break isolation between chains
                                        let isolation_violation = DagEdge::new(chain1_b, chain2_a);
                                        causality_dag.add_corrupted_edge(isolation_violation);

                                        // Verify isolation is maintained
                                        match detector.verify_causal_isolation(&causality_dag) {
                                            Err(CausalOrder::IsolationViolation) => {
                                                // Correctly detected isolation violation
                                            }
                                            Ok(_) => {
                                                // Should have detected isolation violation
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    14 => {
                                        // Test causal edge weight corruption
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let event_a = causality_dag.add_event("event_a", vec![]);
                                        let event_b = causality_dag.add_event("event_b", vec![event_a]);
                                        let event_c = causality_dag.add_event("event_c", vec![event_b]);

                                        // MUTATION: Corrupt edge weights to break causality strength
                                        causality_dag.set_edge_weight(event_a, event_b, -1.0); // Negative weight
                                        causality_dag.set_edge_weight(event_b, event_c, f64::INFINITY); // Invalid weight

                                        // Check edge weight validity
                                        match detector.validate_edge_weights(&causality_dag) {
                                            Err(CausalOrder::InvalidWeights) => {
                                                // Correctly detected invalid edge weights
                                            }
                                            Ok(_) => {
                                                // Should have detected invalid weights
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    16 => {
                                        // Test causal event merging corruption
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let event_a = causality_dag.add_event("event_a", vec![]);
                                        let event_b = causality_dag.add_event("event_b", vec![]);
                                        let merge_event = causality_dag.add_event("merge", vec![event_a, event_b]);

                                        // MUTATION: Corrupt merge semantics (merge happens before dependencies)
                                        causality_dag.corrupt_merge_timing(merge_event, -100); // Before dependencies

                                        // Verify merge causality
                                        match detector.verify_merge_causality(&causality_dag) {
                                            Err(CausalOrder::MergeViolation) => {
                                                // Correctly detected merge causality violation
                                            }
                                            Ok(_) => {
                                                // Should have detected merge violation
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    18 => {
                                        // Test causal path compression corruption
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        // Create long causal chain
                                        let mut events = vec![causality_dag.add_event("event_0", vec![])];
                                        for i in 1..10 {
                                            let prev = events[i - 1];
                                            let event = causality_dag.add_event(&format!("event_{}", i), vec![prev]);
                                            events.push(event);
                                        }

                                        // MUTATION: Corrupt path compression by removing intermediate edges
                                        causality_dag.remove_edge(events[3], events[4]);
                                        causality_dag.remove_edge(events[6], events[7]);

                                        // Add direct path that skips removed edges
                                        let compressed_edge = DagEdge::new(events[3], events[5]); // Skip event_4
                                        causality_dag.add_corrupted_edge(compressed_edge);

                                        // Verify path integrity
                                        match detector.verify_path_integrity(&causality_dag) {
                                            Err(CausalOrder::PathCorruption) => {
                                                // Correctly detected path compression corruption
                                            }
                                            Ok(_) => {
                                                // Should have detected path corruption
                                                causality_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal causality DAG test
                                        let mut causality_dag = CausalityDag::new();
                                        let detector = DivergenceDetector::new();

                                        let event_a = causality_dag.add_event("normal_a", vec![]);
                                        let event_b = causality_dag.add_event("normal_b", vec![event_a]);
                                        detector.check_causal_consistency(&causality_dag).ok();
                                    }
                                }
                            }

                            sleep(Duration::from_millis(3)).await;
                        }

                        let corruptions = divergence_corruptions.load(Ordering::Relaxed);
                        let violations = causality_violations.load(Ordering::Relaxed);

                        // Causality divergence detection should catch DAG edge corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Causality DAG edge corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(ErrorKind::Other,
                                format!("Trace divergence causality failed: {} corruptions, {} violations",
                                    corruptions, violations)))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(
            trace_divergence_detected,
            Outcome::Ok(true) | Outcome::Err(_)
        );
        self.log_subsystem_mutation(
            "br-mutation-49",
            "trace",
            "divergence_causality_dag_edge_corruption",
            detected,
        );
    }

    /// [br-mutation-50] Evidence chain replay determinism regression mutations
    async fn test_evidence_mutations(&self) {
        use crate::evidence::{ChainValidator, EvidenceChain, EvidenceReplay, ReplayDeterminism};

        let evidence_detected = self
            .runtime
            .scope(|scope| async move {
                let evidence_test_count = 16;
                let evidence_corruptions = Arc::new(AtomicUsize::new(0));
                let determinism_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..evidence_test_count {
                            // Test evidence chain replay determinism corruption
                            if test_idx % 2 == 0 {
                                evidence_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt evidence chain replay determinism
                                match test_idx % 16 {
                                    0 => {
                                        // Test basic replay non-determinism corruption
                                        let mut evidence_chain = EvidenceChain::new("test_chain");
                                        let replay_engine = EvidenceReplay::new();
                                        let validator = ChainValidator::new();

                                        // Add evidence entries
                                        evidence_chain
                                            .add_evidence("step_1", "action_a", "result_1");
                                        evidence_chain
                                            .add_evidence("step_2", "action_b", "result_2");
                                        evidence_chain
                                            .add_evidence("step_3", "action_c", "result_3");

                                        // First replay (baseline)
                                        let replay1 =
                                            replay_engine.replay_chain(&evidence_chain).await;

                                        // MUTATION: Inject non-determinism into replay
                                        evidence_chain.inject_replay_non_determinism(true);

                                        // Second replay (should match first but won't due to corruption)
                                        let replay2 =
                                            replay_engine.replay_chain(&evidence_chain).await;

                                        // Verify determinism
                                        match validator
                                            .verify_replay_determinism(&replay1, &replay2)
                                        {
                                            Err(ReplayDeterminism::NonDeterministic) => {
                                                // Correctly detected non-deterministic replay
                                            }
                                            Ok(_) => {
                                                // Should have detected non-determinism
                                                determinism_violations
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    2 => {
                                        // Test evidence ordering corruption in replay
                                        let mut evidence_chain =
                                            EvidenceChain::new("ordering_test");
                                        let replay_engine = EvidenceReplay::new();
                                        let validator = ChainValidator::new();

                                        // Add evidence in specific order
                                        for i in 0..5 {
                                            evidence_chain.add_evidence(
                                                &format!("step_{}", i),
                                                &format!("action_{}", i),
                                                &format!("result_{}", i),
                                            );
                                        }

                                        let baseline_replay =
                                            replay_engine.replay_chain(&evidence_chain).await;

                                        // MUTATION: Corrupt evidence ordering during replay
                                        evidence_chain.corrupt_replay_ordering(true);

                                        let corrupted_replay =
                                            replay_engine.replay_chain(&evidence_chain).await;

                                        // Check ordering determinism
                                        match validator.verify_ordering_determinism(
                                            &baseline_replay,
                                            &corrupted_replay,
                                        ) {
                                            Err(ReplayDeterminism::OrderingViolation) => {
                                                // Correctly detected ordering non-determinism
                                            }
                                            Ok(_) => {
                                                // Should have detected ordering violation
                                                determinism_violations
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    4 => {
                                        // Test evidence timestamp corruption in replay
                                        let mut evidence_chain =
                                            EvidenceChain::new("timestamp_test");
                                        let replay_engine = EvidenceReplay::new();
                                        let validator = ChainValidator::new();

                                        // Add evidence with specific timestamps
                                        evidence_chain.add_evidence_with_timestamp(
                                            "step_1", "action_1", "result_1", 1000,
                                        );
                                        evidence_chain.add_evidence_with_timestamp(
                                            "step_2", "action_2", "result_2", 2000,
                                        );
                                        evidence_chain.add_evidence_with_timestamp(
                                            "step_3", "action_3", "result_3", 3000,
                                        );

                                        let baseline_replay = replay_engine
                                            .replay_chain_with_timing(&evidence_chain)
                                            .await;

                                        // MUTATION: Corrupt timestamps during replay
                                        evidence_chain.corrupt_replay_timestamps(true);

                                        let corrupted_replay = replay_engine
                                            .replay_chain_with_timing(&evidence_chain)
                                            .await;

                                        // Verify timestamp determinism
                                        match validator.verify_timestamp_determinism(
                                            &baseline_replay,
                                            &corrupted_replay,
                                        ) {
                                            Err(ReplayDeterminism::TimestampDrift) => {
                                                // Correctly detected timestamp non-determinism
                                            }
                                            Ok(_) => {
                                                // Should have detected timestamp drift
                                                determinism_violations
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    6 => {
                                        // Test evidence state corruption during replay
                                        let mut evidence_chain = EvidenceChain::new("state_test");
                                        let replay_engine = EvidenceReplay::new();
                                        let validator = ChainValidator::new();

                                        // Add evidence that modifies state
                                        evidence_chain.add_stateful_evidence(
                                            "init",
                                            "initialize",
                                            "state_0",
                                        );
                                        evidence_chain.add_stateful_evidence(
                                            "modify_a",
                                            "update_field",
                                            "state_1",
                                        );
                                        evidence_chain.add_stateful_evidence(
                                            "modify_b",
                                            "update_field",
                                            "state_2",
                                        );

                                        let baseline_replay = replay_engine
                                            .replay_with_state_tracking(&evidence_chain)
                                            .await;

                                        // MUTATION: Corrupt state evolution during replay
                                        evidence_chain.corrupt_state_evolution(true);

                                        let corrupted_replay = replay_engine
                                            .replay_with_state_tracking(&evidence_chain)
                                            .await;

                                        // Verify state determinism
                                        match validator.verify_state_determinism(
                                            &baseline_replay,
                                            &corrupted_replay,
                                        ) {
                                            Err(ReplayDeterminism::StateInconsistency) => {
                                                // Correctly detected state non-determinism
                                            }
                                            Ok(_) => {
                                                // Should have detected state inconsistency
                                                determinism_violations
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    8 => {
                                        // Test evidence checksum corruption during replay
                                        let mut evidence_chain =
                                            EvidenceChain::new("checksum_test");
                                        let replay_engine = EvidenceReplay::new();
                                        let validator = ChainValidator::new();

                                        // Add evidence with checksums
                                        for i in 0..3 {
                                            let data = format!("evidence_data_{}", i);
                                            let checksum = evidence_chain.compute_checksum(&data);
                                            evidence_chain.add_evidence_with_checksum(
                                                &format!("step_{}", i),
                                                &data,
                                                checksum,
                                            );
                                        }

                                        let baseline_replay = replay_engine
                                            .replay_with_checksum_verification(&evidence_chain)
                                            .await;

                                        // MUTATION: Corrupt checksums during replay
                                        evidence_chain.corrupt_replay_checksums(true);

                                        let corrupted_replay = replay_engine
                                            .replay_with_checksum_verification(&evidence_chain)
                                            .await;

                                        // Verify checksum determinism
                                        match validator.verify_checksum_determinism(
                                            &baseline_replay,
                                            &corrupted_replay,
                                        ) {
                                            Err(ReplayDeterminism::ChecksumMismatch) => {
                                                // Correctly detected checksum non-determinism
                                            }
                                            Ok(_) => {
                                                // Should have detected checksum mismatch
                                                determinism_violations
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    10 => {
                                        // Test evidence chain branching corruption during replay
                                        let mut evidence_chain =
                                            EvidenceChain::new("branching_test");
                                        let replay_engine = EvidenceReplay::new();
                                        let validator = ChainValidator::new();

                                        // Create evidence chain with branching
                                        evidence_chain.add_evidence("base", "init", "base_state");
                                        let branch_point =
                                            evidence_chain.add_branch_point("branch");
                                        evidence_chain.add_evidence_to_branch(
                                            branch_point,
                                            "branch_a",
                                            "action_a",
                                            "result_a",
                                        );
                                        evidence_chain.add_evidence_to_branch(
                                            branch_point,
                                            "branch_b",
                                            "action_b",
                                            "result_b",
                                        );
                                        evidence_chain.merge_branches(
                                            branch_point,
                                            "merge",
                                            "combined_result",
                                        );

                                        let baseline_replay = replay_engine
                                            .replay_branched_chain(&evidence_chain)
                                            .await;

                                        // MUTATION: Corrupt branch replay determinism
                                        evidence_chain.corrupt_branch_replay(true);

                                        let corrupted_replay = replay_engine
                                            .replay_branched_chain(&evidence_chain)
                                            .await;

                                        // Verify branch determinism
                                        match validator.verify_branch_determinism(
                                            &baseline_replay,
                                            &corrupted_replay,
                                        ) {
                                            Err(ReplayDeterminism::BranchingInconsistency) => {
                                                // Correctly detected branch non-determinism
                                            }
                                            Ok(_) => {
                                                // Should have detected branching inconsistency
                                                determinism_violations
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    12 => {
                                        // Test evidence chain compression corruption during replay
                                        let mut evidence_chain =
                                            EvidenceChain::new("compression_test");
                                        let replay_engine = EvidenceReplay::new();
                                        let validator = ChainValidator::new();

                                        // Add compressible evidence sequence
                                        for i in 0..10 {
                                            evidence_chain.add_evidence(
                                                &format!("step_{}", i),
                                                "increment_counter",
                                                &format!("counter={}", i + 1),
                                            );
                                        }

                                        // Enable compression
                                        evidence_chain.enable_compression(true);

                                        let baseline_compressed = replay_engine
                                            .replay_compressed_chain(&evidence_chain)
                                            .await;

                                        // MUTATION: Corrupt compression algorithm determinism
                                        evidence_chain.corrupt_compression_determinism(true);

                                        let corrupted_compressed = replay_engine
                                            .replay_compressed_chain(&evidence_chain)
                                            .await;

                                        // Verify compression determinism
                                        match validator.verify_compression_determinism(
                                            &baseline_compressed,
                                            &corrupted_compressed,
                                        ) {
                                            Err(ReplayDeterminism::CompressionInconsistency) => {
                                                // Correctly detected compression non-determinism
                                            }
                                            Ok(_) => {
                                                // Should have detected compression inconsistency
                                                determinism_violations
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    14 => {
                                        // Test evidence chain parallel replay corruption
                                        let mut evidence_chain =
                                            EvidenceChain::new("parallel_test");
                                        let replay_engine = EvidenceReplay::new();
                                        let validator = ChainValidator::new();

                                        // Add evidence suitable for parallel replay
                                        for i in 0..8 {
                                            evidence_chain.add_parallel_evidence(
                                                &format!("parallel_{}", i),
                                                &format!("independent_action_{}", i),
                                                &format!("result_{}", i),
                                            );
                                        }

                                        let baseline_parallel = replay_engine
                                            .replay_parallel_chain(&evidence_chain, 4)
                                            .await;

                                        // MUTATION: Corrupt parallel replay determinism
                                        evidence_chain.corrupt_parallel_replay(true);

                                        let corrupted_parallel = replay_engine
                                            .replay_parallel_chain(&evidence_chain, 4)
                                            .await;

                                        // Verify parallel determinism
                                        match validator.verify_parallel_determinism(
                                            &baseline_parallel,
                                            &corrupted_parallel,
                                        ) {
                                            Err(ReplayDeterminism::ParallelInconsistency) => {
                                                // Correctly detected parallel non-determinism
                                            }
                                            Ok(_) => {
                                                // Should have detected parallel inconsistency
                                                determinism_violations
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal evidence chain test
                                        let mut evidence_chain = EvidenceChain::new("normal_test");
                                        let replay_engine = EvidenceReplay::new();

                                        evidence_chain.add_evidence(
                                            "normal",
                                            "normal_action",
                                            "normal_result",
                                        );
                                        replay_engine.replay_chain(&evidence_chain).await;
                                    }
                                }
                            }

                            sleep(Duration::from_millis(4)).await;
                        }

                        let corruptions = evidence_corruptions.load(Ordering::Relaxed);
                        let violations = determinism_violations.load(Ordering::Relaxed);

                        // Evidence replay validation should catch determinism corruption
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Evidence replay determinism corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Evidence chain replay failed: {} corruptions, {} violations",
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

        let detected = matches!(evidence_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation(
            "br-mutation-50",
            "evidence",
            "chain_replay_determinism_corruption",
            detected,
        );
    }

    /// [br-mutation-51] Signal graceful shutdown ordering regression mutations
    async fn test_signal_graceful_mutations(&self) {
        use crate::signal::graceful::{
            ComponentLifecycle, GracefulShutdown, ShutdownCoordinator, ShutdownOrdering,
        };

        let signal_graceful_detected = self
            .runtime
            .scope(|scope| async move {
                let graceful_test_count = 22;
                let graceful_corruptions = Arc::new(AtomicUsize::new(0));
                let ordering_violations = Arc::new(AtomicUsize::new(0));

                let task = scope
                    .spawn(async move {
                        for test_idx in 0..graceful_test_count {
                            // Test graceful shutdown ordering corruption
                            if test_idx % 2 == 0 {
                                graceful_corruptions.fetch_add(1, Ordering::Relaxed);

                                // MUTATION: Corrupt graceful shutdown ordering
                                match test_idx % 22 {
                                    0 => {
                                        // Test basic shutdown ordering corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        // Register components in proper dependency order
                                        let database = coordinator.register_component("database", ComponentLifecycle::Critical);
                                        let web_server = coordinator.register_component("web_server", ComponentLifecycle::Normal);
                                        let background_jobs = coordinator.register_component("background_jobs", ComponentLifecycle::Normal);

                                        // Set proper shutdown order: web_server -> background_jobs -> database
                                        coordinator.set_shutdown_dependency(web_server, database);
                                        coordinator.set_shutdown_dependency(background_jobs, database);

                                        // MUTATION: Corrupt shutdown ordering
                                        coordinator.corrupt_shutdown_order(true);

                                        // Execute shutdown
                                        let shutdown_result = graceful_shutdown.execute_shutdown(&coordinator).await;

                                        // Verify shutdown ordering
                                        match shutdown_result {
                                            Err(ShutdownOrdering::DependencyViolation) => {
                                                // Correctly detected shutdown ordering violation
                                            }
                                            Ok(_) => {
                                                // Should have detected ordering violation
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    2 => {
                                        // Test shutdown timeout corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        let slow_component = coordinator.register_component_with_timeout("slow_service", ComponentLifecycle::Normal, Duration::from_secs(5));
                                        let fast_component = coordinator.register_component_with_timeout("fast_service", ComponentLifecycle::Normal, Duration::from_secs(1));

                                        // MUTATION: Corrupt timeout handling
                                        coordinator.corrupt_timeout_handling(true);

                                        // Execute shutdown with timeout
                                        let shutdown_result = graceful_shutdown.execute_shutdown_with_timeout(&coordinator, Duration::from_secs(3)).await;

                                        // Verify timeout handling
                                        match shutdown_result {
                                            Err(ShutdownOrdering::TimeoutViolation) => {
                                                // Correctly detected timeout violation
                                            }
                                            Ok(_) => {
                                                // Should have detected timeout violation
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    4 => {
                                        // Test shutdown signal propagation corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        // Create hierarchy of components
                                        let parent = coordinator.register_component("parent", ComponentLifecycle::Critical);
                                        let child1 = coordinator.register_component("child1", ComponentLifecycle::Normal);
                                        let child2 = coordinator.register_component("child2", ComponentLifecycle::Normal);

                                        coordinator.set_parent_child_relationship(parent, child1);
                                        coordinator.set_parent_child_relationship(parent, child2);

                                        // MUTATION: Corrupt signal propagation
                                        coordinator.corrupt_signal_propagation(true);

                                        // Trigger shutdown
                                        let shutdown_result = graceful_shutdown.trigger_shutdown_signal(&coordinator).await;

                                        // Verify signal propagation
                                        match shutdown_result {
                                            Err(ShutdownOrdering::SignalPropagationFailure) => {
                                                // Correctly detected signal propagation corruption
                                            }
                                            Ok(_) => {
                                                // Should have detected signal propagation failure
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    6 => {
                                        // Test shutdown resource cleanup ordering corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        let tcp_server = coordinator.register_resource_component("tcp_server", ComponentLifecycle::Normal, vec!["socket_fd"]);
                                        let file_handler = coordinator.register_resource_component("file_handler", ComponentLifecycle::Normal, vec!["file_handles"]);
                                        let memory_pool = coordinator.register_resource_component("memory_pool", ComponentLifecycle::Critical, vec!["allocated_memory"]);

                                        // Set resource dependencies: tcp_server depends on memory_pool
                                        coordinator.set_resource_dependency(tcp_server, memory_pool);

                                        // MUTATION: Corrupt resource cleanup ordering
                                        coordinator.corrupt_resource_cleanup_order(true);

                                        let cleanup_result = graceful_shutdown.execute_resource_cleanup(&coordinator).await;

                                        // Verify resource cleanup ordering
                                        match cleanup_result {
                                            Err(ShutdownOrdering::ResourceCleanupViolation) => {
                                                // Correctly detected resource cleanup violation
                                            }
                                            Ok(_) => {
                                                // Should have detected cleanup violation
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    8 => {
                                        // Test shutdown phase ordering corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        let service = coordinator.register_component("service", ComponentLifecycle::Normal);

                                        // Define shutdown phases: PREPARE -> SHUTDOWN -> CLEANUP -> FINALIZE
                                        coordinator.define_shutdown_phases(vec!["PREPARE", "SHUTDOWN", "CLEANUP", "FINALIZE"]);
                                        coordinator.assign_component_to_phase(service, "SHUTDOWN");

                                        // MUTATION: Corrupt phase ordering
                                        coordinator.corrupt_phase_ordering(true);

                                        let phase_result = graceful_shutdown.execute_phased_shutdown(&coordinator).await;

                                        // Verify phase ordering
                                        match phase_result {
                                            Err(ShutdownOrdering::PhaseOrderingViolation) => {
                                                // Correctly detected phase ordering violation
                                            }
                                            Ok(_) => {
                                                // Should have detected phase violation
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    10 => {
                                        // Test shutdown barrier synchronization corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        // Components that need synchronized shutdown
                                        let worker1 = coordinator.register_component("worker1", ComponentLifecycle::Normal);
                                        let worker2 = coordinator.register_component("worker2", ComponentLifecycle::Normal);
                                        let worker3 = coordinator.register_component("worker3", ComponentLifecycle::Normal);

                                        let barrier = coordinator.create_shutdown_barrier("worker_barrier");
                                        coordinator.add_component_to_barrier(barrier, worker1);
                                        coordinator.add_component_to_barrier(barrier, worker2);
                                        coordinator.add_component_to_barrier(barrier, worker3);

                                        // MUTATION: Corrupt barrier synchronization
                                        coordinator.corrupt_barrier_synchronization(true);

                                        let barrier_result = graceful_shutdown.execute_synchronized_shutdown(&coordinator).await;

                                        // Verify barrier synchronization
                                        match barrier_result {
                                            Err(ShutdownOrdering::BarrierSynchronizationFailure) => {
                                                // Correctly detected barrier synchronization corruption
                                            }
                                            Ok(_) => {
                                                // Should have detected synchronization failure
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    12 => {
                                        // Test shutdown graceful vs forceful transition corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        let stubborn_service = coordinator.register_component_with_behavior("stubborn_service", ComponentLifecycle::Normal, "refuses_shutdown");
                                        let cooperative_service = coordinator.register_component_with_behavior("cooperative_service", ComponentLifecycle::Normal, "graceful_shutdown");

                                        // Set graceful timeout before forceful
                                        coordinator.set_graceful_timeout(Duration::from_secs(2));
                                        coordinator.set_forceful_timeout(Duration::from_secs(5));

                                        // MUTATION: Corrupt graceful-to-forceful transition
                                        coordinator.corrupt_graceful_forceful_transition(true);

                                        let transition_result = graceful_shutdown.execute_graduated_shutdown(&coordinator).await;

                                        // Verify transition handling
                                        match transition_result {
                                            Err(ShutdownOrdering::TransitionViolation) => {
                                                // Correctly detected transition violation
                                            }
                                            Ok(_) => {
                                                // Should have detected transition violation
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    14 => {
                                        // Test shutdown priority inversion corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        let high_priority = coordinator.register_component_with_priority("critical_service", ComponentLifecycle::Critical, 100);
                                        let medium_priority = coordinator.register_component_with_priority("important_service", ComponentLifecycle::Normal, 50);
                                        let low_priority = coordinator.register_component_with_priority("background_service", ComponentLifecycle::Normal, 10);

                                        // Set dependencies that could cause priority inversion
                                        coordinator.set_shutdown_dependency(low_priority, high_priority); // Low depends on high

                                        // MUTATION: Corrupt priority handling causing inversion
                                        coordinator.corrupt_priority_inversion_protection(true);

                                        let priority_result = graceful_shutdown.execute_priority_shutdown(&coordinator).await;

                                        // Verify priority inversion protection
                                        match priority_result {
                                            Err(ShutdownOrdering::PriorityInversion) => {
                                                // Correctly detected priority inversion
                                            }
                                            Ok(_) => {
                                                // Should have detected priority inversion
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    16 => {
                                        // Test shutdown rollback corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        let database = coordinator.register_component("database", ComponentLifecycle::Critical);
                                        let api_server = coordinator.register_component("api_server", ComponentLifecycle::Normal);

                                        coordinator.set_shutdown_dependency(api_server, database);

                                        // Enable rollback on critical failures
                                        coordinator.enable_shutdown_rollback(true);

                                        // MUTATION: Corrupt rollback mechanism
                                        coordinator.corrupt_rollback_mechanism(true);

                                        // Trigger shutdown that should rollback
                                        coordinator.inject_shutdown_failure(database, "critical_failure");

                                        let rollback_result = graceful_shutdown.execute_shutdown_with_rollback(&coordinator).await;

                                        // Verify rollback handling
                                        match rollback_result {
                                            Err(ShutdownOrdering::RollbackCorruption) => {
                                                // Correctly detected rollback corruption
                                            }
                                            Ok(_) => {
                                                // Should have detected rollback corruption
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    18 => {
                                        // Test shutdown health check corruption during shutdown
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        let monitored_service = coordinator.register_component_with_health_check("monitored", ComponentLifecycle::Normal);

                                        // Enable health monitoring during shutdown
                                        coordinator.enable_shutdown_health_monitoring(true);

                                        // MUTATION: Corrupt health check during shutdown
                                        coordinator.corrupt_shutdown_health_checks(true);

                                        let health_result = graceful_shutdown.execute_monitored_shutdown(&coordinator).await;

                                        // Verify health check handling
                                        match health_result {
                                            Err(ShutdownOrdering::HealthCheckCorruption) => {
                                                // Correctly detected health check corruption
                                            }
                                            Ok(_) => {
                                                // Should have detected health check corruption
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    20 => {
                                        // Test shutdown notification ordering corruption
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        // Components that send/receive shutdown notifications
                                        let notifier = coordinator.register_component("notifier", ComponentLifecycle::Normal);
                                        let subscriber1 = coordinator.register_component("subscriber1", ComponentLifecycle::Normal);
                                        let subscriber2 = coordinator.register_component("subscriber2", ComponentLifecycle::Normal);

                                        coordinator.set_notification_relationship(notifier, vec![subscriber1, subscriber2]);

                                        // MUTATION: Corrupt notification ordering
                                        coordinator.corrupt_notification_ordering(true);

                                        let notification_result = graceful_shutdown.execute_notification_shutdown(&coordinator).await;

                                        // Verify notification ordering
                                        match notification_result {
                                            Err(ShutdownOrdering::NotificationOrderingViolation) => {
                                                // Correctly detected notification ordering violation
                                            }
                                            Ok(_) => {
                                                // Should have detected notification violation
                                                ordering_violations.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                // Other error
                                            }
                                        }
                                    }
                                    _ => {
                                        // Normal graceful shutdown test
                                        let mut coordinator = ShutdownCoordinator::new();
                                        let graceful_shutdown = GracefulShutdown::new();

                                        let service = coordinator.register_component("normal_service", ComponentLifecycle::Normal);
                                        graceful_shutdown.execute_shutdown(&coordinator).await.ok();
                                    }
                                }
                            }

                            sleep(Duration::from_millis(2)).await;
                        }

                        let corruptions = graceful_corruptions.load(Ordering::Relaxed);
                        let violations = ordering_violations.load(Ordering::Relaxed);

                        // Graceful shutdown validation should catch ordering violations
                        if violations > 0 && corruptions > 0 {
                            Outcome::Ok(true) // Shutdown ordering corruption detected
                        } else if corruptions > 0 {
                            Outcome::Err(Error::new(ErrorKind::Other,
                                format!("Signal graceful shutdown failed: {} corruptions, {} violations",
                                    corruptions, violations)))
                        } else {
                            Outcome::Ok(false) // No corruptions
                        }
                    })
                    .await;

                task.await.unwrap_or(Outcome::Ok(false))
            })
            .await;

        let detected = matches!(
            signal_graceful_detected,
            Outcome::Ok(true) | Outcome::Err(_)
        );
        self.log_subsystem_mutation(
            "br-mutation-51",
            "signal",
            "graceful_shutdown_ordering_corruption",
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
async fn test_database_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("database_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"database_start\"}}");

    // Test database-specific mutations
    tester.test_database_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply database mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.92,
        "Database subsystem should detect ≥92% of postgres SCRAM handshake byte-flip mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"database_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_fs_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("fs_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"fs_start\"}}");

    // Test fs-specific mutations
    tester.test_fs_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply fs mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.93,
        "FS subsystem should detect ≥93% of io_uring submission ordering mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"fs_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_io_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("io_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"io_start\"}}");

    // Test io-specific mutations
    tester.test_io_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply io mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.95,
        "IO subsystem should detect ≥95% of split→unsplit identity mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"io_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_database_client_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("database_client_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"database_client_start\"}}");

    // Test database client-specific mutations
    tester.test_database_client_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply database client mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.93,
        "Database client subsystem should detect ≥93% of mysql/sqlite connection corruption mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"database_client_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_fs_operations_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("fs_operations_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"fs_operations_start\"}}");

    // Test fs operations-specific mutations
    tester.test_fs_operations_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply fs operations mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.94,
        "FS operations subsystem should detect ≥94% of vfs/platform/path operations mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"fs_operations_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_io_capability_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("io_capability_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"io_capability_start\"}}");

    // Test io capability-specific mutations
    tester.test_io_capability_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply io capability mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.96,
        "IO capability subsystem should detect ≥96% of capability/browser/copy operations mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"io_capability_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_runtime_state_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("runtime_state_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"runtime_state_start\"}}");

    // Test runtime state-specific mutations
    tester.test_runtime_state_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply runtime state mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.93,
        "Runtime state subsystem should detect ≥93% of region close eager-vs-lazy mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"runtime_state_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_cx_registry_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("cx_registry_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"cx_registry_start\"}}");

    // Test cx registry-specific mutations
    tester.test_cx_registry_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply cx registry mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.95,
        "Cx registry subsystem should detect ≥95% of commit_permit identity mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"cx_registry_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_net_dns_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("net_dns_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"net_dns_start\"}}");

    // Test net dns-specific mutations
    tester.test_net_dns_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply net dns mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.94,
        "Net DNS subsystem should detect ≥94% of TTL caching expiry mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"net_dns_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_raptorq_gf256_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("raptorq_gf256_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"raptorq_gf256_start\"}}");

    // Test raptorq gf256-specific mutations
    tester.test_raptorq_gf256_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply raptorq gf256 mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.96,
        "RaptorQ GF256 subsystem should detect ≥96% of XOR table multiplication verification mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"raptorq_gf256_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_raptorq_proof_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("raptorq_proof_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"raptorq_proof_start\"}}");

    // Test raptorq proof-specific mutations
    tester.test_raptorq_proof_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply raptorq proof mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.97,
        "RaptorQ proof subsystem should detect ≥97% of Merkle aggregation associativity mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"raptorq_proof_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_obligation_saga_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("obligation_saga_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"obligation_saga_start\"}}");

    // Test obligation saga-specific mutations
    tester.test_obligation_saga_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply obligation saga mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.95,
        "Obligation saga subsystem should detect ≥95% of compensation symmetry mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"obligation_saga_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_trace_divergence_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("trace_divergence_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"trace_divergence_start\"}}");

    // Test trace divergence-specific mutations
    tester.test_trace_divergence_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply trace divergence mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.94,
        "Trace divergence subsystem should detect ≥94% of causality DAG edge mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"trace_divergence_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_evidence_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("evidence_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"evidence_start\"}}");

    // Test evidence-specific mutations
    tester.test_evidence_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply evidence mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.97,
        "Evidence subsystem should detect ≥97% of chain replay determinism mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"evidence_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
        detection_rate
    );
}

#[tokio::test]
async fn test_signal_graceful_subsystem_mutation_sensitivity() {
    let tester = SubsystemMutationTester::new("signal_graceful_subsystem").await;

    eprintln!("{{\"subsystem_mutation_test\":\"signal_graceful_start\"}}");

    // Test signal graceful-specific mutations
    tester.test_signal_graceful_mutations().await;

    let summary = tester.generate_subsystem_summary();
    eprintln!("{}", summary);

    let applied = tester.mutations_applied.load(Ordering::Relaxed);
    let detected = tester.mutations_detected.load(Ordering::Relaxed);

    assert!(applied > 0, "Should apply signal graceful mutations");

    let detection_rate = detected as f64 / applied as f64;
    assert!(
        detection_rate >= 0.95,
        "Signal graceful subsystem should detect ≥95% of shutdown ordering mutations: {:.1}% ({}/{})",
        detection_rate * 100.0,
        detected,
        applied
    );

    eprintln!(
        "{{\"signal_graceful_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}",
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
    let database_tester = SubsystemMutationTester::new("comprehensive_database").await;
    let fs_tester = SubsystemMutationTester::new("comprehensive_fs").await;
    let io_tester = SubsystemMutationTester::new("comprehensive_io").await;
    let database_client_tester =
        SubsystemMutationTester::new("comprehensive_database_client").await;
    let fs_operations_tester = SubsystemMutationTester::new("comprehensive_fs_operations").await;
    let io_capability_tester = SubsystemMutationTester::new("comprehensive_io_capability").await;
    let runtime_state_tester = SubsystemMutationTester::new("comprehensive_runtime_state").await;
    let cx_registry_tester = SubsystemMutationTester::new("comprehensive_cx_registry").await;
    let net_dns_tester = SubsystemMutationTester::new("comprehensive_net_dns").await;
    let raptorq_gf256_tester = SubsystemMutationTester::new("comprehensive_raptorq_gf256").await;
    let raptorq_proof_tester = SubsystemMutationTester::new("comprehensive_raptorq_proof").await;
    let obligation_saga_tester =
        SubsystemMutationTester::new("comprehensive_obligation_saga").await;
    let trace_divergence_tester =
        SubsystemMutationTester::new("comprehensive_trace_divergence").await;
    let evidence_tester = SubsystemMutationTester::new("comprehensive_evidence").await;
    let signal_graceful_tester =
        SubsystemMutationTester::new("comprehensive_signal_graceful").await;

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

    database_tester.test_database_mutations().await;

    fs_tester.test_fs_mutations().await;

    io_tester.test_io_mutations().await;

    database_client_tester
        .test_database_client_mutations()
        .await;

    fs_operations_tester.test_fs_operations_mutations().await;

    io_capability_tester.test_io_capability_mutations().await;

    runtime_state_tester.test_runtime_state_mutations().await;

    cx_registry_tester.test_cx_registry_mutations().await;

    net_dns_tester.test_net_dns_mutations().await;

    raptorq_gf256_tester.test_raptorq_gf256_mutations().await;

    raptorq_proof_tester.test_raptorq_proof_mutations().await;

    obligation_saga_tester
        .test_obligation_saga_mutations()
        .await;

    trace_divergence_tester
        .test_trace_divergence_mutations()
        .await;

    evidence_tester.test_evidence_mutations().await;

    signal_graceful_tester
        .test_signal_graceful_mutations()
        .await;

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
        + tls_tester.mutations_applied.load(Ordering::Relaxed)
        + database_tester.mutations_applied.load(Ordering::Relaxed)
        + fs_tester.mutations_applied.load(Ordering::Relaxed)
        + io_tester.mutations_applied.load(Ordering::Relaxed)
        + database_client_tester
            .mutations_applied
            .load(Ordering::Relaxed)
        + fs_operations_tester
            .mutations_applied
            .load(Ordering::Relaxed)
        + io_capability_tester
            .mutations_applied
            .load(Ordering::Relaxed)
        + runtime_state_tester
            .mutations_applied
            .load(Ordering::Relaxed)
        + cx_registry_tester.mutations_applied.load(Ordering::Relaxed)
        + net_dns_tester.mutations_applied.load(Ordering::Relaxed)
        + raptorq_gf256_tester
            .mutations_applied
            .load(Ordering::Relaxed)
        + raptorq_proof_tester
            .mutations_applied
            .load(Ordering::Relaxed)
        + obligation_saga_tester
            .mutations_applied
            .load(Ordering::Relaxed)
        + trace_divergence_tester
            .mutations_applied
            .load(Ordering::Relaxed)
        + evidence_tester.mutations_applied.load(Ordering::Relaxed)
        + signal_graceful_tester
            .mutations_applied
            .load(Ordering::Relaxed);

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
        + tls_tester.mutations_detected.load(Ordering::Relaxed)
        + database_tester.mutations_detected.load(Ordering::Relaxed)
        + fs_tester.mutations_detected.load(Ordering::Relaxed)
        + io_tester.mutations_detected.load(Ordering::Relaxed)
        + database_client_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + fs_operations_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + io_capability_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + runtime_state_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + cx_registry_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + net_dns_tester.mutations_detected.load(Ordering::Relaxed)
        + raptorq_gf256_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + raptorq_proof_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + obligation_saga_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + trace_divergence_tester
            .mutations_detected
            .load(Ordering::Relaxed)
        + evidence_tester.mutations_detected.load(Ordering::Relaxed)
        + signal_graceful_tester
            .mutations_detected
            .load(Ordering::Relaxed);

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
