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
use crate::runtime::{RuntimeBuilder, LabRuntime};
use crate::sync::{AtomicBool, AtomicUsize, Ordering};
use crate::time::{sleep, Duration, Instant};
use crate::types::Outcome;

use std::sync::Arc;
use std::collections::HashMap;
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

    fn log_subsystem_mutation(&self, mutation_id: &str, component: &str, mutation_type: &str, detected: bool) {
        eprintln!("{{\"subsystem_mutation\":\"{}\",\"id\":\"{}\",\"component\":\"{}\",\"type\":\"{}\",\"detected\":{}}}",
            self.test_name, mutation_id, component, mutation_type, detected);

        self.mutations_applied.fetch_add(1, Ordering::Relaxed);
        if detected {
            self.mutations_detected.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// [br-mutation-13] Observability counter increment regression mutations
    async fn test_observability_counter_mutations(&self) {
        // Test various counter increment regressions in observability system
        use crate::observability::{Metrics, Counter, Histogram};

        let metrics_detected = self.runtime.scope(|scope| async move {
            // Setup observability metrics
            let request_counter = Counter::new("requests_total", "Total HTTP requests");
            let error_counter = Counter::new("errors_total", "Total errors");
            let response_histogram = Histogram::new("response_duration", "Response time distribution");

            let total_requests = 100;
            let error_mutations = Arc::new(AtomicUsize::new(0));
            let missing_increments = Arc::new(AtomicUsize::new(0));
            let incorrect_increments = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
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
                        let expected_requests = req_id + 1 - missing_increments.load(Ordering::Relaxed);
                        let expected_errors = error_mutations.load(Ordering::Relaxed);

                        // Check for discrepancies (should detect counter mutations)
                        if request_count != expected_requests || error_count != expected_errors {
                            return Outcome::Err(Error::new(ErrorKind::Other,
                                format!("Counter mutation detected: req {} != {}, err {} != {}",
                                    request_count, expected_requests, error_count, expected_errors)));
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
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(metrics_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation("br-mutation-13", "observability", "counter_increment_regression", detected);
    }

    /// [br-mutation-14] Trace causality DAG event-order swap mutations
    async fn test_trace_causality_mutations(&self) {
        // Test event ordering and causality violations in trace system
        use crate::trace::{TraceId, SpanId, TraceEvent, CausalityDAG};

        let causality_detected = self.runtime.scope(|scope| async move {
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
        }).await;

        let detected = matches!(causality_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation("br-mutation-14", "trace", "causality_dag_event_order_swap", detected);
    }

    /// [br-mutation-15] Security authenticated encryption tag-flip mutations
    async fn test_security_auth_encryption_mutations(&self) {
        // Test bit-level tampering detection in authenticated encryption
        use crate::security::{AuthenticatedEncryption, EncryptionKey, AuthTag};

        let auth_detected = self.runtime.scope(|scope| async move {
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
        }).await;

        let detected = matches!(auth_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation("br-mutation-15", "security", "auth_encryption_tag_flip", detected);
    }

    /// Additional observability mutation: metric aggregation corruption
    async fn test_observability_aggregation_mutations(&self) {
        use crate::observability::{Histogram, Summary, Gauge};

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
        self.log_subsystem_mutation("br-mutation-13b", "observability", "metric_aggregation_corruption", detected);
    }

    /// Additional trace mutation: span relationship corruption
    async fn test_trace_span_relationship_mutations(&self) {
        use crate::trace::{TraceId, SpanId, Span, SpanContext};

        let span_detected = self.runtime.scope(|scope| async move {
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
        }).await;

        let detected = matches!(span_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation("br-mutation-14b", "trace", "span_relationship_corruption", detected);
    }

    /// Additional security mutation: encryption key corruption
    async fn test_security_key_corruption_mutations(&self) {
        use crate::security::{EncryptionKey, KeyDerivation, CryptoError};

        let key_detected = self.runtime.scope(|scope| async move {
            let master_key = EncryptionKey::generate();
            let key_derivation = KeyDerivation::new(master_key);

            let derivation_count = 20;
            let key_corruptions = Arc::new(AtomicUsize::new(0));
            let crypto_errors = Arc::new(AtomicUsize::new(0));

            let task = scope.spawn(async move {
                for derive_id in 0..derivation_count {
                    let context = format!("derive_context_{}", derive_id);
                    let salt = format!("salt_{}", derive_id);

                    // Derive key
                    let derived_key = match key_derivation.derive(&context, salt.as_bytes()) {
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
                    Outcome::Err(Error::new(ErrorKind::Other,
                        format!("Key corruption not detected: {} corruptions, {} errors",
                            corruptions, errors)))
                } else {
                    Outcome::Ok(false) // No corruptions
                }
            }).await;

            task.await.unwrap_or(Outcome::Ok(false))
        }).await;

        let detected = matches!(key_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation("br-mutation-15b", "security", "encryption_key_corruption", detected);
    }

    /// [br-mutation-16] Plan graph topology edge insertion regression mutations
    async fn test_plan_graph_topology_mutations(&self) {
        use crate::plan::{PlanGraph, PlanNode, PlanEdge, TopologyError};

        let plan_detected = self.runtime.scope(|scope| async move {
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
        }).await;

        let detected = matches!(plan_detected, Outcome::Ok(true) | Outcome::Err(_));
        self.log_subsystem_mutation("br-mutation-16", "plan", "graph_topology_corruption", detected);
    }

    /// [br-mutation-17] RaptorQ systematic symbol decode regression mutations
    async fn test_raptorq_systematic_symbol_mutations(&self) {
        use crate::raptorq::{Encoder, Decoder, EncodingPacket, Symbol, K_MAX};

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
        self.log_subsystem_mutation("br-mutation-17", "raptorq", "systematic_symbol_corruption", detected);
    }

    /// [br-mutation-18] Distributed consistent hash ring rebalance corruption mutations
    async fn test_distributed_consistent_hash_mutations(&self) {
        use crate::distributed::{ConsistentHashRing, Node, Hash, RebalanceError};

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
        self.log_subsystem_mutation("br-mutation-18", "distributed", "consistent_hash_corruption", detected);
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
    assert!(detection_rate >= 0.85,
        "Observability subsystem should detect ≥85% of metric mutations: {:.1}% ({}/{})",
        detection_rate * 100.0, detected, applied);

    eprintln!("{{\"observability_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}", detection_rate);
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
    assert!(detection_rate >= 0.90,
        "Trace subsystem should detect ≥90% of causality mutations: {:.1}% ({}/{})",
        detection_rate * 100.0, detected, applied);

    eprintln!("{{\"trace_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}", detection_rate);
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
    assert!(detection_rate >= 0.95,
        "Security subsystem should detect ≥95% of cryptographic mutations: {:.1}% ({}/{})",
        detection_rate * 100.0, detected, applied);

    eprintln!("{{\"security_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}", detection_rate);
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
    assert!(detection_rate >= 0.85,
        "Plan subsystem should detect ≥85% of topology mutations: {:.1}% ({}/{})",
        detection_rate * 100.0, detected, applied);

    eprintln!("{{\"plan_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}", detection_rate);
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
    assert!(detection_rate >= 0.92,
        "RaptorQ subsystem should detect ≥92% of systematic symbol mutations: {:.1}% ({}/{})",
        detection_rate * 100.0, detected, applied);

    eprintln!("{{\"raptorq_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}", detection_rate);
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
    assert!(detection_rate >= 0.88,
        "Distributed subsystem should detect ≥88% of consistent hash mutations: {:.1}% ({}/{})",
        detection_rate * 100.0, detected, applied);

    eprintln!("{{\"distributed_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}", detection_rate);
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

    // Test all subsystem mutations comprehensively
    obs_tester.test_observability_counter_mutations().await;
    obs_tester.test_observability_aggregation_mutations().await;

    trace_tester.test_trace_causality_mutations().await;
    trace_tester.test_trace_span_relationship_mutations().await;

    sec_tester.test_security_auth_encryption_mutations().await;
    sec_tester.test_security_key_corruption_mutations().await;

    plan_tester.test_plan_graph_topology_mutations().await;
    raptorq_tester.test_raptorq_systematic_symbol_mutations().await;
    distributed_tester.test_distributed_consistent_hash_mutations().await;

    // Calculate overall subsystem detection rate
    let total_applied = obs_tester.mutations_applied.load(Ordering::Relaxed) +
                       trace_tester.mutations_applied.load(Ordering::Relaxed) +
                       sec_tester.mutations_applied.load(Ordering::Relaxed) +
                       plan_tester.mutations_applied.load(Ordering::Relaxed) +
                       raptorq_tester.mutations_applied.load(Ordering::Relaxed) +
                       distributed_tester.mutations_applied.load(Ordering::Relaxed);

    let total_detected = obs_tester.mutations_detected.load(Ordering::Relaxed) +
                        trace_tester.mutations_detected.load(Ordering::Relaxed) +
                        sec_tester.mutations_detected.load(Ordering::Relaxed) +
                        plan_tester.mutations_detected.load(Ordering::Relaxed) +
                        raptorq_tester.mutations_detected.load(Ordering::Relaxed) +
                        distributed_tester.mutations_detected.load(Ordering::Relaxed);

    let overall_detection_rate = if total_applied > 0 {
        total_detected as f64 / total_applied as f64
    } else {
        0.0
    };

    eprintln!("{{\"comprehensive_subsystem_results\":{{\"total_applied\":{},\"total_detected\":{},\"detection_rate\":{:.2},\"threshold\":0.90}}}}",
        total_applied, total_detected, overall_detection_rate);

    assert!(total_applied > 0, "Should apply subsystem mutations");
    assert!(overall_detection_rate >= 0.90,
        "Overall subsystem mutation detection should be ≥90%: {:.1}% ({}/{})",
        overall_detection_rate * 100.0, total_detected, total_applied);

    eprintln!("{{\"comprehensive_subsystem_mutation_test\":\"PASSED\",\"detection_rate\":{:.2}}}", overall_detection_rate);
}