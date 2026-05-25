//! Integration tests for obligation/no_aliasing_proof ↔ cx/macaroon integration.
//!
//! These tests verify that attenuated macaroons correctly preserve the no-aliasing
//! invariant across capability passing between execution contexts.
//!
//! Key integration points tested:
//! - Macaroon attenuation preserving no-aliasing proofs
//! - Cross-scope capability passing with maintained invariants
//! - Complex attenuation chains without capability confusion
//! - Stress scenarios with multiple attenuated capabilities
//! - Edge cases in nested capability delegation

#[cfg(all(test, feature = "real-service-e2e"))]
mod integration_tests {
    use crate::cx::{Cx, macaroon::{Macaroon, MacaroonBuilder, Caveat, AttenuationError}};
    use crate::obligation::no_aliasing_proof::{NoAliasingProof, AliasingViolation, CapabilityRef, ProofContext};
    use crate::runtime::{RuntimeBuilder, Runtime};
    use crate::types::{TaskId, RegionId, Budget, Outcome};
    use crate::record::obligation::ObligationRecord;
    use crate::error::AsupersyncError;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Test harness for obligation no-aliasing proof and macaroon integration testing.
    struct NoAliasingMacaroonTestHarness {
        runtime: Arc<Runtime>,
        proof_contexts: HashMap<TaskId, ProofContext>,
        macaroon_registry: HashMap<String, Macaroon>,
        attenuation_chains: HashMap<String, Vec<Caveat>>,
        capability_refs: HashSet<CapabilityRef>,
        stats: Arc<Mutex<NoAliasingMacaroonStats>>,
    }

    #[derive(Debug, Default, Clone)]
    struct NoAliasingMacaroonStats {
        /// Total macaroons created
        macaroons_created: u64,
        /// Total attenuations performed
        attenuations_performed: u64,
        /// Capability passes attempted
        capability_passes_attempted: u64,
        /// Capability passes that preserved no-aliasing
        no_aliasing_preserved: u64,
        /// Aliasing violations detected
        aliasing_violations: u64,
        /// Proof validations performed
        proof_validations: u64,
        /// Complex attenuation chains created
        complex_chains_created: u64,
        /// Cross-scope transfers completed
        cross_scope_transfers: u64,
    }

    impl NoAliasingMacaroonTestHarness {
        fn new() -> Result<Self, AsupersyncError> {
            let runtime = Arc::new(
                RuntimeBuilder::new()
                    .with_deterministic_scheduler()
                    .with_capability_security()
                    .build()?
            );

            Ok(Self {
                runtime,
                proof_contexts: HashMap::new(),
                macaroon_registry: HashMap::new(),
                attenuation_chains: HashMap::new(),
                capability_refs: HashSet::new(),
                stats: Arc::new(Mutex::new(NoAliasingMacaroonStats::default())),
            })
        }

        fn create_root_macaroon(&mut self, cx: &Cx, identifier: &str) -> Result<Macaroon, AsupersyncError> {
            let macaroon = MacaroonBuilder::new()
                .with_location("asupersync://test")
                .with_identifier(identifier)
                .with_key_material(b"test-secret-key")
                .build(cx)?;

            self.macaroon_registry.insert(identifier.to_string(), macaroon.clone());
            {
                let mut stats = self.stats.lock().unwrap();
                stats.macaroons_created += 1;
            }

            Ok(macaroon)
        }

        fn attenuate_macaroon(&mut self, cx: &Cx, base_id: &str, caveats: Vec<Caveat>) -> Result<(String, Macaroon), AsupersyncError> {
            let base_macaroon = self.macaroon_registry.get(base_id)
                .ok_or_else(|| AsupersyncError::InvalidState("Base macaroon not found".into()))?;

            let mut attenuated = base_macaroon.clone();
            for caveat in &caveats {
                attenuated = attenuated.add_first_party_caveat(cx, caveat.clone())?;
            }

            let attenuated_id = format!("{}_attenuated_{}", base_id, self.attenuation_chains.len());
            self.macaroon_registry.insert(attenuated_id.clone(), attenuated.clone());
            self.attenuation_chains.insert(attenuated_id.clone(), caveats);

            {
                let mut stats = self.stats.lock().unwrap();
                stats.attenuations_performed += 1;
                if caveats.len() > 3 {
                    stats.complex_chains_created += 1;
                }
            }

            Ok((attenuated_id, attenuated))
        }

        fn create_no_aliasing_proof(&mut self, cx: &Cx, task_id: TaskId, capability_refs: Vec<CapabilityRef>) -> Result<NoAliasingProof, AsupersyncError> {
            let proof_context = ProofContext::new(task_id, capability_refs.clone())?;
            let proof = NoAliasingProof::generate(cx, &proof_context)?;

            for cap_ref in capability_refs {
                self.capability_refs.insert(cap_ref);
            }
            self.proof_contexts.insert(task_id, proof_context);

            {
                let mut stats = self.stats.lock().unwrap();
                stats.proof_validations += 1;
            }

            Ok(proof)
        }

        fn validate_capability_pass(&mut self, cx: &Cx, from_task: TaskId, to_task: TaskId, macaroon_id: &str) -> Result<bool, AsupersyncError> {
            let macaroon = self.macaroon_registry.get(macaroon_id)
                .ok_or_else(|| AsupersyncError::InvalidState("Macaroon not found for validation".into()))?;

            let from_context = self.proof_contexts.get(&from_task);
            let to_context = self.proof_contexts.get(&to_task);

            {
                let mut stats = self.stats.lock().unwrap();
                stats.capability_passes_attempted += 1;
            }

            // Simulate no-aliasing validation across macaroon transfer
            let no_aliasing_preserved = match (from_context, to_context) {
                (Some(from_ctx), Some(to_ctx)) => {
                    // Check that capability transfer doesn't create aliasing
                    let combined_refs: HashSet<_> = from_ctx.capability_refs().iter()
                        .chain(to_ctx.capability_refs().iter())
                        .collect();

                    // Validate no overlapping capability references that could create aliases
                    let has_potential_aliasing = combined_refs.len() < (from_ctx.capability_refs().len() + to_ctx.capability_refs().len());

                    if has_potential_aliasing {
                        let mut stats = self.stats.lock().unwrap();
                        stats.aliasing_violations += 1;
                        false
                    } else {
                        // Validate macaroon caveats maintain separation
                        let maintains_separation = self.validate_attenuation_separation(macaroon_id)?;
                        if maintains_separation {
                            let mut stats = self.stats.lock().unwrap();
                            stats.no_aliasing_preserved += 1;
                            stats.cross_scope_transfers += 1;
                        }
                        maintains_separation
                    }
                }
                _ => {
                    // Missing proof context - assume violation
                    let mut stats = self.stats.lock().unwrap();
                    stats.aliasing_violations += 1;
                    false
                }
            };

            Ok(no_aliasing_preserved)
        }

        fn validate_attenuation_separation(&self, macaroon_id: &str) -> Result<bool, AsupersyncError> {
            let caveats = self.attenuation_chains.get(macaroon_id);
            match caveats {
                Some(caveat_chain) => {
                    // Check that attenuation chain maintains proper capability separation
                    let mut scopes = HashSet::new();
                    for caveat in caveat_chain {
                        let scope_id = caveat.extract_scope_restriction()?;
                        if scopes.contains(&scope_id) {
                            return Ok(false); // Duplicate scope could create aliasing
                        }
                        scopes.insert(scope_id);
                    }
                    Ok(true)
                }
                None => Ok(true) // Root macaroon, assume valid
            }
        }

        fn get_stats(&self) -> NoAliasingMacaroonStats {
            self.stats.lock().unwrap().clone()
        }
    }

    /// Custom caveat implementation for testing
    #[derive(Debug, Clone)]
    struct TestCaveat {
        scope_restriction: String,
        time_bound: Option<Duration>,
        resource_limit: Option<u64>,
    }

    impl Caveat for TestCaveat {
        fn verify(&self, _context: &crate::cx::macaroon::VerificationContext) -> Result<bool, AttenuationError> {
            Ok(true) // Simplified for testing
        }

        fn extract_scope_restriction(&self) -> Result<String, AsupersyncError> {
            Ok(self.scope_restriction.clone())
        }
    }

    #[tokio::test]
    async fn test_basic_macaroon_attenuation_preserves_no_aliasing() -> Result<(), AsupersyncError> {
        let mut harness = NoAliasingMacaroonTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime.region(Budget::default(), |cx| async move {
            // Create root macaroon
            let root_macaroon = harness.create_root_macaroon(cx, "test-root")?;

            // Create capability references for no-aliasing proof
            let cap_refs = vec![
                CapabilityRef::new("resource-a", "read"),
                CapabilityRef::new("resource-b", "write"),
            ];

            let task_id = cx.task_id();
            let proof = harness.create_no_aliasing_proof(cx, task_id, cap_refs)?;

            // Attenuate macaroon with scope restrictions
            let caveats = vec![
                Box::new(TestCaveat {
                    scope_restriction: "limited-scope".to_string(),
                    time_bound: Some(Duration::from_secs(60)),
                    resource_limit: Some(1024),
                }) as Box<dyn Caveat>
            ];

            let (attenuated_id, _attenuated_macaroon) = harness.attenuate_macaroon(cx, "test-root", caveats)?;

            // Validate that attenuation preserved no-aliasing
            let target_task = TaskId::new();
            let target_cap_refs = vec![CapabilityRef::new("resource-c", "read")];
            harness.create_no_aliasing_proof(cx, target_task, target_cap_refs)?;

            let preserved = harness.validate_capability_pass(cx, task_id, target_task, &attenuated_id)?;
            assert!(preserved, "Macaroon attenuation should preserve no-aliasing invariant");

            let stats = harness.get_stats();
            assert_eq!(stats.macaroons_created, 1);
            assert_eq!(stats.attenuations_performed, 1);
            assert_eq!(stats.no_aliasing_preserved, 1);
            assert_eq!(stats.aliasing_violations, 0);

            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_cross_scope_capability_passing_maintains_separation() -> Result<(), AsupersyncError> {
        let mut harness = NoAliasingMacaroonTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime.region(Budget::default(), |cx| async move {
            // Create multiple scoped macaroons
            let scope_a_macaroon = harness.create_root_macaroon(cx, "scope-a")?;
            let scope_b_macaroon = harness.create_root_macaroon(cx, "scope-b")?;

            // Create non-overlapping capability references
            let scope_a_refs = vec![
                CapabilityRef::new("db-connection", "read"),
                CapabilityRef::new("file-handle-1", "write"),
            ];
            let scope_b_refs = vec![
                CapabilityRef::new("network-socket", "send"),
                CapabilityRef::new("file-handle-2", "read"),
            ];

            let task_a = TaskId::new();
            let task_b = TaskId::new();
            harness.create_no_aliasing_proof(cx, task_a, scope_a_refs)?;
            harness.create_no_aliasing_proof(cx, task_b, scope_b_refs)?;

            // Attenuate each macaroon with different restrictions
            let scope_a_caveats = vec![
                Box::new(TestCaveat {
                    scope_restriction: "database-only".to_string(),
                    time_bound: Some(Duration::from_secs(30)),
                    resource_limit: Some(512),
                }) as Box<dyn Caveat>
            ];
            let scope_b_caveats = vec![
                Box::new(TestCaveat {
                    scope_restriction: "network-only".to_string(),
                    time_bound: Some(Duration::from_secs(45)),
                    resource_limit: Some(256),
                }) as Box<dyn Caveat>
            ];

            let (attenuated_a_id, _) = harness.attenuate_macaroon(cx, "scope-a", scope_a_caveats)?;
            let (attenuated_b_id, _) = harness.attenuate_macaroon(cx, "scope-b", scope_b_caveats)?;

            // Cross-scope capability passing should preserve separation
            let a_to_b_preserved = harness.validate_capability_pass(cx, task_a, task_b, &attenuated_a_id)?;
            let b_to_a_preserved = harness.validate_capability_pass(cx, task_b, task_a, &attenuated_b_id)?;

            assert!(a_to_b_preserved, "Cross-scope capability pass A->B should preserve no-aliasing");
            assert!(b_to_a_preserved, "Cross-scope capability pass B->A should preserve no-aliasing");

            let stats = harness.get_stats();
            assert_eq!(stats.macaroons_created, 2);
            assert_eq!(stats.attenuations_performed, 2);
            assert_eq!(stats.cross_scope_transfers, 2);
            assert_eq!(stats.aliasing_violations, 0);

            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_complex_attenuation_chains_maintain_invariants() -> Result<(), AsupersyncError> {
        let mut harness = NoAliasingMacaroonTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime.region(Budget::default(), |cx| async move {
            // Create root macaroon
            let _root = harness.create_root_macaroon(cx, "complex-root")?;

            // Create complex attenuation chain
            let mut current_id = "complex-root".to_string();
            let attenuation_levels = vec![
                vec![Box::new(TestCaveat {
                    scope_restriction: "level-1".to_string(),
                    time_bound: Some(Duration::from_secs(3600)),
                    resource_limit: Some(4096),
                }) as Box<dyn Caveat>],
                vec![Box::new(TestCaveat {
                    scope_restriction: "level-2".to_string(),
                    time_bound: Some(Duration::from_secs(1800)),
                    resource_limit: Some(2048),
                }) as Box<dyn Caveat>],
                vec![Box::new(TestCaveat {
                    scope_restriction: "level-3".to_string(),
                    time_bound: Some(Duration::from_secs(900)),
                    resource_limit: Some(1024),
                }) as Box<dyn Caveat>],
                vec![Box::new(TestCaveat {
                    scope_restriction: "level-4".to_string(),
                    time_bound: Some(Duration::from_secs(300)),
                    resource_limit: Some(512),
                }) as Box<dyn Caveat>],
            ];

            // Build attenuation chain
            for (level, caveats) in attenuation_levels.into_iter().enumerate() {
                let (new_id, _) = harness.attenuate_macaroon(cx, &current_id, caveats)?;
                current_id = new_id;

                // Create proof context for each level
                let task_id = TaskId::new();
                let cap_refs = vec![CapabilityRef::new(&format!("resource-level-{}", level), "access")];
                harness.create_no_aliasing_proof(cx, task_id, cap_refs)?;
            }

            // Validate that deeply attenuated macaroon maintains no-aliasing
            let source_task = TaskId::new();
            let target_task = TaskId::new();

            let source_refs = vec![CapabilityRef::new("deep-source", "read")];
            let target_refs = vec![CapabilityRef::new("deep-target", "write")];

            harness.create_no_aliasing_proof(cx, source_task, source_refs)?;
            harness.create_no_aliasing_proof(cx, target_task, target_refs)?;

            let preserved = harness.validate_capability_pass(cx, source_task, target_task, &current_id)?;
            assert!(preserved, "Complex attenuation chain should preserve no-aliasing invariants");

            let stats = harness.get_stats();
            assert_eq!(stats.complex_chains_created, 1); // 4+ caveats in final chain
            assert!(stats.attenuations_performed >= 4);
            assert_eq!(stats.aliasing_violations, 0);

            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_aliasing_violation_detection() -> Result<(), AsupersyncError> {
        let mut harness = NoAliasingMacaroonTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime.region(Budget::default(), |cx| async move {
            // Create macaroon
            let _root = harness.create_root_macaroon(cx, "aliasing-test")?;

            // Create overlapping capability references (should cause aliasing violation)
            let overlapping_refs_a = vec![
                CapabilityRef::new("shared-resource", "read"),
                CapabilityRef::new("exclusive-resource-a", "write"),
            ];
            let overlapping_refs_b = vec![
                CapabilityRef::new("shared-resource", "write"), // Same resource, different access!
                CapabilityRef::new("exclusive-resource-b", "read"),
            ];

            let task_a = TaskId::new();
            let task_b = TaskId::new();
            harness.create_no_aliasing_proof(cx, task_a, overlapping_refs_a)?;
            harness.create_no_aliasing_proof(cx, task_b, overlapping_refs_b)?;

            // Attempt capability pass with overlapping resources
            let preserved = harness.validate_capability_pass(cx, task_a, task_b, "aliasing-test")?;
            assert!(!preserved, "Should detect aliasing violation with overlapping resource access");

            let stats = harness.get_stats();
            assert!(stats.aliasing_violations > 0, "Should have recorded aliasing violations");
            assert_eq!(stats.no_aliasing_preserved, 0);

            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_stress_multiple_attenuated_capabilities() -> Result<(), AsupersyncError> {
        let mut harness = NoAliasingMacaroonTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime.region(Budget::default(), |cx| async move {
            let start_time = Instant::now();
            let num_macaroons = 20;
            let num_attenuations_per_macaroon = 5;

            // Create multiple root macaroons
            for i in 0..num_macaroons {
                let root_id = format!("stress-root-{}", i);
                harness.create_root_macaroon(cx, &root_id)?;

                // Create multiple attenuations per root
                let mut current_id = root_id;
                for j in 0..num_attenuations_per_macaroon {
                    let caveats = vec![
                        Box::new(TestCaveat {
                            scope_restriction: format!("stress-scope-{}-{}", i, j),
                            time_bound: Some(Duration::from_secs(60 * (j + 1) as u64)),
                            resource_limit: Some(1024 * (j + 1) as u64),
                        }) as Box<dyn Caveat>
                    ];

                    let (new_id, _) = harness.attenuate_macaroon(cx, &current_id, caveats)?;
                    current_id = new_id;

                    // Create proof context
                    let task_id = TaskId::new();
                    let cap_refs = vec![CapabilityRef::new(&format!("stress-resource-{}-{}", i, j), "access")];
                    harness.create_no_aliasing_proof(cx, task_id, cap_refs)?;
                }
            }

            // Validate cross-capability interactions don't create aliasing
            let mut preserved_count = 0;
            for i in 0..10 { // Sample validations
                let source_task = TaskId::new();
                let target_task = TaskId::new();

                let source_refs = vec![CapabilityRef::new(&format!("validation-source-{}", i), "read")];
                let target_refs = vec![CapabilityRef::new(&format!("validation-target-{}", i), "write")];

                harness.create_no_aliasing_proof(cx, source_task, source_refs)?;
                harness.create_no_aliasing_proof(cx, target_task, target_refs)?;

                let macaroon_id = format!("stress-root-{}_attenuated_{}", i % num_macaroons, 4); // Use deeply attenuated
                if harness.validate_capability_pass(cx, source_task, target_task, &macaroon_id)? {
                    preserved_count += 1;
                }
            }

            let elapsed = start_time.elapsed();
            let stats = harness.get_stats();

            println!("Stress test completed in {:?}", elapsed);
            println!("Macaroons created: {}", stats.macaroons_created);
            println!("Attenuations performed: {}", stats.attenuations_performed);
            println!("Capability passes preserved: {}/{}", preserved_count, 10);
            println!("Complex chains created: {}", stats.complex_chains_created);

            assert_eq!(stats.macaroons_created, num_macaroons as u64);
            assert_eq!(stats.attenuations_performed, (num_macaroons * num_attenuations_per_macaroon) as u64);
            assert!(preserved_count >= 8, "Most capability passes should preserve no-aliasing under stress");
            assert!(elapsed < Duration::from_secs(10), "Stress test should complete within reasonable time");

            Ok(())
        }).await
    }

    #[tokio::test]
    async fn test_nested_capability_delegation_edge_cases() -> Result<(), AsupersyncError> {
        let mut harness = NoAliasingMacaroonTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime.region(Budget::default(), |cx| async move {
            // Create root macaroon for delegation chain
            let _root = harness.create_root_macaroon(cx, "delegation-root")?;

            // Create deeply nested delegation chain with edge cases
            let delegation_levels = vec![
                ("service-layer", Duration::from_secs(3600)),
                ("middleware-layer", Duration::from_secs(1800)),
                ("application-layer", Duration::from_secs(900)),
                ("component-layer", Duration::from_secs(450)),
                ("function-layer", Duration::from_secs(225)),
                ("operation-layer", Duration::from_secs(60)),
            ];

            let mut current_id = "delegation-root".to_string();
            let mut task_chain = Vec::new();

            for (layer_name, time_bound) in delegation_levels {
                // Create attenuation for this layer
                let caveats = vec![
                    Box::new(TestCaveat {
                        scope_restriction: layer_name.to_string(),
                        time_bound: Some(time_bound),
                        resource_limit: Some(2048), // Fixed limit to test edge case
                    }) as Box<dyn Caveat>
                ];

                let (new_id, _) = harness.attenuate_macaroon(cx, &current_id, caveats)?;

                // Create task with unique capabilities for each layer
                let task_id = TaskId::new();
                let cap_refs = vec![
                    CapabilityRef::new(&format!("{}-primary", layer_name), "execute"),
                    CapabilityRef::new(&format!("{}-secondary", layer_name), "monitor"),
                ];
                harness.create_no_aliasing_proof(cx, task_id, cap_refs)?;

                task_chain.push((task_id, new_id.clone()));
                current_id = new_id;
            }

            // Validate capability flow through entire delegation chain
            let mut all_preserved = true;
            for i in 0..task_chain.len().saturating_sub(1) {
                let (source_task, _) = &task_chain[i];
                let (target_task, macaroon_id) = &task_chain[i + 1];

                let preserved = harness.validate_capability_pass(cx, *source_task, *target_task, macaroon_id)?;
                if !preserved {
                    all_preserved = false;
                    break;
                }
            }

            // Test edge case: circular delegation attempt (should be prevented)
            let first_task = task_chain[0].0;
            let last_task = task_chain[task_chain.len() - 1].0;
            let last_macaroon = &task_chain[task_chain.len() - 1].1;

            // This should still preserve no-aliasing as capabilities are distinct
            let circular_preserved = harness.validate_capability_pass(cx, last_task, first_task, last_macaroon)?;

            assert!(all_preserved, "Nested delegation chain should preserve no-aliasing invariants");
            assert!(circular_preserved, "Circular delegation with distinct capabilities should be valid");

            let stats = harness.get_stats();
            assert_eq!(stats.attenuations_performed, 6); // One per delegation level
            assert!(stats.cross_scope_transfers >= 6);
            assert_eq!(stats.aliasing_violations, 0);

            Ok(())
        }).await
    }
}