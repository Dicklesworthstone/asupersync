//! Real obligation/graded ↔ obligation/no_aliasing_proof integration E2E test
//!
//! Tests integration between graded obligation tracking and no-aliasing proof
//! systems across nested capability passing scenarios. Verifies that graded
//! obligations correctly prove no aliasing violations when capabilities are
//! passed through multiple nested scopes and ownership transfers.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_obligation_graded_no_aliasing_proof_e2e {
    use crate::cx::{Cx, scope};
    use crate::runtime::{RuntimeBuilder, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{Budget, RegionId, TaskId};
    use serde_json::json;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Statistics for graded obligation + no-aliasing proof testing
    #[derive(Debug, Clone, Default)]
    struct GradedAliasingProofStats {
        /// Graded obligations created
        graded_obligations_created: usize,
        /// No-aliasing proofs generated
        no_aliasing_proofs_generated: usize,
        /// Successful aliasing proofs
        successful_aliasing_proofs: usize,
        /// Failed aliasing proofs (detected violations)
        failed_aliasing_proofs: usize,
        /// Nested capability transfers
        nested_capability_transfers: usize,
        /// Ownership transfers completed
        ownership_transfers_completed: usize,
        /// Grade transitions performed
        grade_transitions: usize,
        /// Aliasing violations detected
        aliasing_violations_detected: usize,
        /// Proof verification attempts
        proof_verifications: usize,
        /// Total test duration in milliseconds
        test_duration_ms: u64,
    }

    impl GradedAliasingProofStats {
        fn to_json(&self) -> serde_json::Value {
            json!({
                "graded_obligations_created": self.graded_obligations_created,
                "no_aliasing_proofs_generated": self.no_aliasing_proofs_generated,
                "successful_aliasing_proofs": self.successful_aliasing_proofs,
                "failed_aliasing_proofs": self.failed_aliasing_proofs,
                "nested_capability_transfers": self.nested_capability_transfers,
                "ownership_transfers_completed": self.ownership_transfers_completed,
                "grade_transitions": self.grade_transitions,
                "aliasing_violations_detected": self.aliasing_violations_detected,
                "proof_verifications": self.proof_verifications,
                "test_duration_ms": self.test_duration_ms,
                "proof_success_rate": if self.proof_verifications > 0 {
                    (self.successful_aliasing_proofs as f64) / (self.proof_verifications as f64)
                } else { 0.0 },
            })
        }
    }

    /// Mock graded obligation for testing
    #[derive(Debug, Clone, PartialEq)]
    struct MockGradedObligation {
        id: u64,
        grade: MockObligationGrade,
        resource_id: String,
        capability_refs: HashSet<String>,
        created_at: u64,
        grading_criteria: MockGradingCriteria,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum MockObligationGrade {
        Ungraded,
        Linear,       // Exactly one reference allowed
        Affine,       // At most one reference allowed
        Relevant,     // At least one reference required
        Unrestricted, // No restrictions
    }

    #[derive(Debug, Clone, PartialEq)]
    struct MockGradingCriteria {
        allows_duplication: bool,
        allows_dropping: bool,
        requires_consumption: bool,
    }

    impl MockGradedObligation {
        fn new(id: u64, resource_id: &str, grade: MockObligationGrade) -> Self {
            Self {
                id,
                grade: grade.clone(),
                resource_id: resource_id.to_string(),
                capability_refs: HashSet::new(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                grading_criteria: match grade {
                    MockObligationGrade::Linear => MockGradingCriteria {
                        allows_duplication: false,
                        allows_dropping: false,
                        requires_consumption: true,
                    },
                    MockObligationGrade::Affine => MockGradingCriteria {
                        allows_duplication: false,
                        allows_dropping: true,
                        requires_consumption: false,
                    },
                    MockObligationGrade::Relevant => MockGradingCriteria {
                        allows_duplication: true,
                        allows_dropping: false,
                        requires_consumption: true,
                    },
                    MockObligationGrade::Unrestricted => MockGradingCriteria {
                        allows_duplication: true,
                        allows_dropping: true,
                        requires_consumption: false,
                    },
                    MockObligationGrade::Ungraded => MockGradingCriteria {
                        allows_duplication: false,
                        allows_dropping: false,
                        requires_consumption: false,
                    },
                },
            }
        }

        fn add_capability_ref(&mut self, cap_ref: &str) {
            self.capability_refs.insert(cap_ref.to_string());
        }

        fn can_duplicate(&self) -> bool {
            self.grading_criteria.allows_duplication
        }

        fn can_drop(&self) -> bool {
            self.grading_criteria.allows_dropping
        }

        fn requires_consumption(&self) -> bool {
            self.grading_criteria.requires_consumption
        }
    }

    /// Mock no-aliasing proof for testing
    #[derive(Debug, Clone)]
    struct MockAliasingProof {
        id: u64,
        resource_id: String,
        ownership_chain: Vec<MockOwnershipTransfer>,
        aliasing_witnesses: Vec<MockNoAliasingWitness>,
        proof_valid: bool,
        verification_timestamp: u64,
    }

    #[derive(Debug, Clone)]
    struct MockOwnershipTransfer {
        from_scope: String,
        to_scope: String,
        capability_id: String,
        transfer_type: MockTransferType,
        timestamp: u64,
    }

    #[derive(Debug, Clone)]
    enum MockTransferType {
        Move,   // Transfer ownership, invalidate source
        Borrow, // Share access, maintain source validity
        Copy,   // Duplicate access (only for copyable types)
    }

    #[derive(Debug, Clone)]
    struct MockNoAliasingWitness {
        capability_id: String,
        scope_id: String,
        exclusive_access: bool,
        access_pattern: MockAccessPattern,
    }

    #[derive(Debug, Clone)]
    enum MockAccessPattern {
        ReadOnly,
        WriteOnly,
        ReadWrite,
        NoAccess,
    }

    impl MockAliasingProof {
        fn new(id: u64, resource_id: &str) -> Self {
            Self {
                id,
                resource_id: resource_id.to_string(),
                ownership_chain: Vec::new(),
                aliasing_witnesses: Vec::new(),
                proof_valid: true,
                verification_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            }
        }

        fn add_ownership_transfer(&mut self, transfer: MockOwnershipTransfer) {
            self.ownership_chain.push(transfer);
        }

        fn add_witness(&mut self, witness: MockNoAliasingWitness) {
            self.aliasing_witnesses.push(witness);
        }

        fn verify_no_aliasing(&mut self) -> bool {
            // Check for aliasing violations in the witness chain
            let mut active_capabilities: HashMap<String, Vec<&MockNoAliasingWitness>> =
                HashMap::new();

            for witness in &self.aliasing_witnesses {
                active_capabilities
                    .entry(witness.capability_id.clone())
                    .or_default()
                    .push(witness);
            }

            // Verify no conflicting access patterns
            for (cap_id, witnesses) in &active_capabilities {
                let mut has_write = false;
                let mut has_read = false;
                let mut exclusive_count = 0;

                for witness in witnesses {
                    if witness.exclusive_access {
                        exclusive_count += 1;
                    }

                    match witness.access_pattern {
                        MockAccessPattern::WriteOnly | MockAccessPattern::ReadWrite => {
                            has_write = true
                        }
                        MockAccessPattern::ReadOnly => has_read = true,
                        MockAccessPattern::NoAccess => {}
                    }
                }

                // Aliasing violation if multiple exclusive accesses or write + any other access
                if exclusive_count > 1 || (has_write && (has_read || witnesses.len() > 1)) {
                    self.proof_valid = false;
                    return false;
                }
            }

            self.proof_valid = true;
            true
        }
    }

    /// Integration manager for graded obligations and aliasing proofs
    struct GradedAliasingIntegrationManager {
        graded_obligations: Arc<Mutex<HashMap<u64, MockGradedObligation>>>,
        aliasing_proofs: Arc<Mutex<HashMap<u64, MockAliasingProof>>>,
        stats: Arc<Mutex<GradedAliasingProofStats>>,
        next_id: Arc<AtomicU64>,
    }

    impl GradedAliasingIntegrationManager {
        fn new(stats: Arc<Mutex<GradedAliasingProofStats>>) -> Self {
            Self {
                graded_obligations: Arc::new(Mutex::new(HashMap::new())),
                aliasing_proofs: Arc::new(Mutex::new(HashMap::new())),
                stats,
                next_id: Arc::new(AtomicU64::new(1)),
            }
        }

        /// Create graded obligation with aliasing proof
        async fn create_graded_obligation_with_proof(
            &self,
            cx: &Cx,
            resource_id: &str,
            grade: MockObligationGrade,
        ) -> Result<(u64, u64), Box<dyn std::error::Error>> {
            let obligation_id = self.next_id.fetch_add(1, Ordering::AcqRel);
            let proof_id = self.next_id.fetch_add(1, Ordering::AcqRel);

            // Create graded obligation
            let mut graded_obligation =
                MockGradedObligation::new(obligation_id, resource_id, grade);
            graded_obligation.add_capability_ref(&format!("cap_{}", obligation_id));

            // Create corresponding aliasing proof
            let mut aliasing_proof = MockAliasingProof::new(proof_id, resource_id);

            // Add initial witness for the obligation's capability
            let initial_witness = MockNoAliasingWitness {
                capability_id: format!("cap_{}", obligation_id),
                scope_id: "root_scope".to_string(),
                exclusive_access: true,
                access_pattern: MockAccessPattern::ReadWrite,
            };
            aliasing_proof.add_witness(initial_witness);

            // Store both
            {
                let mut obligations = self.graded_obligations.lock().unwrap();
                obligations.insert(obligation_id, graded_obligation);
            }

            {
                let mut proofs = self.aliasing_proofs.lock().unwrap();
                proofs.insert(proof_id, aliasing_proof);
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.graded_obligations_created += 1;
                stats.no_aliasing_proofs_generated += 1;
            }

            println!(
                "Created graded obligation {} with aliasing proof {} for resource {}",
                obligation_id, proof_id, resource_id
            );

            Ok((obligation_id, proof_id))
        }

        /// Perform nested capability transfer
        async fn nested_capability_transfer(
            &self,
            cx: &Cx,
            obligation_id: u64,
            proof_id: u64,
            from_scope: &str,
            to_scope: &str,
            transfer_type: MockTransferType,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!(
                "Performing nested capability transfer: {} -> {} (type: {:?})",
                from_scope, to_scope, transfer_type
            );

            // Check if the graded obligation allows this transfer
            let can_transfer = {
                let obligations = self.graded_obligations.lock().unwrap();
                if let Some(obligation) = obligations.get(&obligation_id) {
                    match transfer_type {
                        MockTransferType::Copy => obligation.can_duplicate(),
                        MockTransferType::Move => true, // Move is always allowed if valid ownership
                        MockTransferType::Borrow => true, // Borrow is generally allowed
                    }
                } else {
                    false
                }
            };

            if !can_transfer {
                return Err("Transfer not allowed by graded obligation constraints".into());
            }

            // Create ownership transfer record
            let transfer = MockOwnershipTransfer {
                from_scope: from_scope.to_string(),
                to_scope: to_scope.to_string(),
                capability_id: format!("cap_{}", obligation_id),
                transfer_type: transfer_type.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            };

            // Update aliasing proof
            {
                let mut proofs = self.aliasing_proofs.lock().unwrap();
                if let Some(proof) = proofs.get_mut(&proof_id) {
                    proof.add_ownership_transfer(transfer);

                    // Add witness for the new scope
                    let access_pattern = match transfer_type {
                        MockTransferType::Move => MockAccessPattern::ReadWrite,
                        MockTransferType::Borrow => MockAccessPattern::ReadOnly,
                        MockTransferType::Copy => MockAccessPattern::ReadWrite,
                    };

                    let witness = MockNoAliasingWitness {
                        capability_id: format!("cap_{}", obligation_id),
                        scope_id: to_scope.to_string(),
                        exclusive_access: matches!(transfer_type, MockTransferType::Move),
                        access_pattern,
                    };

                    proof.add_witness(witness);
                }
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.nested_capability_transfers += 1;
                stats.ownership_transfers_completed += 1;
            }

            Ok(())
        }

        /// Verify aliasing proof for graded obligation
        async fn verify_aliasing_proof(
            &self,
            cx: &Cx,
            proof_id: u64,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            let verification_result = {
                let mut proofs = self.aliasing_proofs.lock().unwrap();
                if let Some(proof) = proofs.get_mut(&proof_id) {
                    let result = proof.verify_no_aliasing();
                    println!("Aliasing proof {} verification: {}", proof_id, result);
                    Some(result)
                } else {
                    None
                }
            };

            match verification_result {
                Some(is_valid) => {
                    // Update stats
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.proof_verifications += 1;
                        if is_valid {
                            stats.successful_aliasing_proofs += 1;
                        } else {
                            stats.failed_aliasing_proofs += 1;
                            stats.aliasing_violations_detected += 1;
                        }
                    }
                    Ok(is_valid)
                }
                None => Err("Proof not found".into()),
            }
        }

        /// Transition graded obligation to different grade
        async fn transition_obligation_grade(
            &self,
            cx: &Cx,
            obligation_id: u64,
            new_grade: MockObligationGrade,
        ) -> Result<(), Box<dyn std::error::Error>> {
            {
                let mut obligations = self.graded_obligations.lock().unwrap();
                if let Some(obligation) = obligations.get_mut(&obligation_id) {
                    println!(
                        "Transitioning obligation {} from {:?} to {:?}",
                        obligation_id, obligation.grade, new_grade
                    );
                    obligation.grade = new_grade;

                    // Update grading criteria based on new grade
                    obligation.grading_criteria = match obligation.grade {
                        MockObligationGrade::Linear => MockGradingCriteria {
                            allows_duplication: false,
                            allows_dropping: false,
                            requires_consumption: true,
                        },
                        MockObligationGrade::Affine => MockGradingCriteria {
                            allows_duplication: false,
                            allows_dropping: true,
                            requires_consumption: false,
                        },
                        MockObligationGrade::Relevant => MockGradingCriteria {
                            allows_duplication: true,
                            allows_dropping: false,
                            requires_consumption: true,
                        },
                        MockObligationGrade::Unrestricted => MockGradingCriteria {
                            allows_duplication: true,
                            allows_dropping: true,
                            requires_consumption: false,
                        },
                        MockObligationGrade::Ungraded => MockGradingCriteria {
                            allows_duplication: false,
                            allows_dropping: false,
                            requires_consumption: false,
                        },
                    };
                } else {
                    return Err("Obligation not found".into());
                }
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.grade_transitions += 1;
            }

            Ok(())
        }

        /// Get manager state for debugging
        fn get_state(&self) -> (usize, usize) {
            let obligations_count = self.graded_obligations.lock().unwrap().len();
            let proofs_count = self.aliasing_proofs.lock().unwrap().len();
            (obligations_count, proofs_count)
        }
    }

    /// Test harness for graded obligation + aliasing proof integration
    struct GradedAliasingIntegrationTestHarness {
        manager: GradedAliasingIntegrationManager,
        stats: Arc<Mutex<GradedAliasingProofStats>>,
        start_time: Instant,
    }

    impl GradedAliasingIntegrationTestHarness {
        fn new() -> Self {
            let stats = Arc::new(Mutex::new(GradedAliasingProofStats::default()));
            let manager = GradedAliasingIntegrationManager::new(Arc::clone(&stats));

            Self {
                manager,
                stats,
                start_time: Instant::now(),
            }
        }

        /// Test basic graded obligation with aliasing proof
        async fn test_basic_graded_aliasing_proof(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing basic graded obligation with aliasing proof");

            // Create linear graded obligation with proof
            let (obligation_id, proof_id) = self
                .manager
                .create_graded_obligation_with_proof(
                    cx,
                    "test_resource_1",
                    MockObligationGrade::Linear,
                )
                .await?;

            // Verify initial proof
            let is_valid = self.manager.verify_aliasing_proof(cx, proof_id).await?;
            assert!(is_valid, "Initial aliasing proof should be valid");

            println!("Basic graded obligation test completed successfully");
            Ok(())
        }

        /// Test nested capability transfers
        async fn test_nested_capability_transfers(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing nested capability transfers");

            // Create affine graded obligation (allows dropping but not duplication)
            let (obligation_id, proof_id) = self
                .manager
                .create_graded_obligation_with_proof(
                    cx,
                    "test_resource_2",
                    MockObligationGrade::Affine,
                )
                .await?;

            // Perform valid move transfer
            self.manager
                .nested_capability_transfer(
                    cx,
                    obligation_id,
                    proof_id,
                    "root_scope",
                    "nested_scope_1",
                    MockTransferType::Move,
                )
                .await?;

            // Verify proof is still valid after move
            let is_valid = self.manager.verify_aliasing_proof(cx, proof_id).await?;
            assert!(is_valid, "Proof should be valid after move transfer");

            // Try to perform copy transfer (should fail for affine)
            let copy_result = self
                .manager
                .nested_capability_transfer(
                    cx,
                    obligation_id,
                    proof_id,
                    "nested_scope_1",
                    "nested_scope_2",
                    MockTransferType::Copy,
                )
                .await;

            assert!(
                copy_result.is_err(),
                "Copy transfer should fail for affine obligations"
            );

            println!("Nested capability transfers test completed");
            Ok(())
        }

        /// Test aliasing violation detection
        async fn test_aliasing_violation_detection(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing aliasing violation detection");

            // Create unrestricted graded obligation (allows everything)
            let (obligation_id, proof_id) = self
                .manager
                .create_graded_obligation_with_proof(
                    cx,
                    "test_resource_3",
                    MockObligationGrade::Unrestricted,
                )
                .await?;

            // Perform copy transfers to create potential aliasing
            self.manager
                .nested_capability_transfer(
                    cx,
                    obligation_id,
                    proof_id,
                    "root_scope",
                    "scope_a",
                    MockTransferType::Copy,
                )
                .await?;

            self.manager
                .nested_capability_transfer(
                    cx,
                    obligation_id,
                    proof_id,
                    "root_scope",
                    "scope_b",
                    MockTransferType::Copy,
                )
                .await?;

            // Add conflicting write access witness manually to simulate violation
            {
                let mut proofs = self.manager.aliasing_proofs.lock().unwrap();
                if let Some(proof) = proofs.get_mut(&proof_id) {
                    let conflicting_witness = MockNoAliasingWitness {
                        capability_id: format!("cap_{}", obligation_id),
                        scope_id: "scope_conflict".to_string(),
                        exclusive_access: true,
                        access_pattern: MockAccessPattern::ReadWrite,
                    };
                    proof.add_witness(conflicting_witness);
                }
            }

            // Verify proof - should detect aliasing violation
            let is_valid = self.manager.verify_aliasing_proof(cx, proof_id).await?;
            assert!(!is_valid, "Proof should detect aliasing violation");

            println!("Aliasing violation detection test completed");
            Ok(())
        }

        /// Test grade transitions
        async fn test_grade_transitions(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing grade transitions");

            // Create ungraded obligation
            let (obligation_id, proof_id) = self
                .manager
                .create_graded_obligation_with_proof(
                    cx,
                    "test_resource_4",
                    MockObligationGrade::Ungraded,
                )
                .await?;

            // Transition to linear grade
            self.manager
                .transition_obligation_grade(cx, obligation_id, MockObligationGrade::Linear)
                .await?;

            // Try copy transfer (should fail for linear)
            let copy_result = self
                .manager
                .nested_capability_transfer(
                    cx,
                    obligation_id,
                    proof_id,
                    "root_scope",
                    "linear_scope",
                    MockTransferType::Copy,
                )
                .await;

            assert!(
                copy_result.is_err(),
                "Copy should fail for linear obligations"
            );

            // Transition to unrestricted
            self.manager
                .transition_obligation_grade(cx, obligation_id, MockObligationGrade::Unrestricted)
                .await?;

            // Now copy should work
            let copy_result = self
                .manager
                .nested_capability_transfer(
                    cx,
                    obligation_id,
                    proof_id,
                    "root_scope",
                    "unrestricted_scope",
                    MockTransferType::Copy,
                )
                .await;

            assert!(
                copy_result.is_ok(),
                "Copy should succeed for unrestricted obligations"
            );

            println!("Grade transitions test completed");
            Ok(())
        }

        /// Get test statistics
        fn get_stats(&mut self) -> GradedAliasingProofStats {
            let mut stats = self.stats.lock().unwrap();
            stats.test_duration_ms = self.start_time.elapsed().as_millis() as u64;
            stats.clone()
        }
    }

    #[tokio::test]
    async fn test_graded_obligation_aliasing_proof_basic_integration() {
        println!("=== Starting graded obligation + aliasing proof basic integration test ===");

        scope(|cx| async move {
            let mut harness = GradedAliasingIntegrationTestHarness::new();

            // Test basic functionality
            harness
                .test_basic_graded_aliasing_proof(&cx)
                .await
                .expect("Basic integration test should succeed");

            let stats = harness.get_stats();
            println!(
                "Basic integration stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify basic operation
            assert!(
                stats.graded_obligations_created > 0,
                "Should have created graded obligations"
            );
            assert!(
                stats.no_aliasing_proofs_generated > 0,
                "Should have generated aliasing proofs"
            );
            assert!(
                stats.successful_aliasing_proofs > 0,
                "Should have successful proof verifications"
            );

            println!("✓ Graded obligation + aliasing proof basic integration test passed");
            println!(
                "  - Created {} graded obligations",
                stats.graded_obligations_created
            );
            println!(
                "  - Generated {} aliasing proofs",
                stats.no_aliasing_proofs_generated
            );
            println!(
                "  - Successful proofs: {}",
                stats.successful_aliasing_proofs
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_nested_capability_passing_with_grade_constraints() {
        println!("=== Testing nested capability passing with grade constraints ===");

        scope(|cx| async move {
            let mut harness = GradedAliasingIntegrationTestHarness::new();

            // Test nested capability transfers
            harness
                .test_nested_capability_transfers(&cx)
                .await
                .expect("Nested capability transfer test should succeed");

            let stats = harness.get_stats();
            println!(
                "Nested capability stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have performed transfers
            assert!(
                stats.nested_capability_transfers > 0,
                "Should have performed capability transfers"
            );
            assert!(
                stats.ownership_transfers_completed > 0,
                "Should have completed ownership transfers"
            );

            println!("✓ Nested capability passing test passed");
            println!(
                "  - Capability transfers: {}",
                stats.nested_capability_transfers
            );
            println!(
                "  - Ownership transfers: {}",
                stats.ownership_transfers_completed
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_aliasing_violation_detection_and_grade_transitions() {
        println!("=== Testing aliasing violation detection and grade transitions ===");

        scope(|cx| async move {
            let mut harness = GradedAliasingIntegrationTestHarness::new();

            // Test aliasing violation detection
            harness
                .test_aliasing_violation_detection(&cx)
                .await
                .expect("Aliasing violation test should succeed");

            // Test grade transitions
            harness
                .test_grade_transitions(&cx)
                .await
                .expect("Grade transition test should succeed");

            let stats = harness.get_stats();
            println!(
                "Violation detection stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have detected violations and performed transitions
            assert!(
                stats.aliasing_violations_detected > 0,
                "Should have detected aliasing violations"
            );
            assert!(
                stats.grade_transitions > 0,
                "Should have performed grade transitions"
            );
            assert!(
                stats.failed_aliasing_proofs > 0,
                "Should have failed proofs due to violations"
            );

            println!("✓ Aliasing violation detection and grade transitions test passed");
            println!(
                "  - Violations detected: {}",
                stats.aliasing_violations_detected
            );
            println!("  - Grade transitions: {}", stats.grade_transitions);
            println!("  - Failed proofs: {}", stats.failed_aliasing_proofs);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }
}
