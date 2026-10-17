    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::obligation::choreography::{
        example_lease_renewal, example_saga_compensation, example_scatter_gather_disjoint,
        example_two_phase_commit,
    };

    fn pipeline() -> SagaPipeline {
        SagaPipeline::new()
    }

    // ------------------------------------------------------------------
    // Pipeline generation — two-phase commit
    // ------------------------------------------------------------------

    #[test]
    fn generate_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert_eq!(output.protocol_name, "two_phase_commit");
        assert_eq!(output.participants.len(), 2);
        assert!(output.participants.contains_key("coordinator"));
        assert!(output.participants.contains_key("worker"));
    }

    #[test]
    fn two_phase_commit_coordinator_saga_plan() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        assert!(!coord.saga_plan.steps.is_empty());

        // Coordinator sends: reserve, commit, abort
        let send_steps: Vec<_> = coord
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Send)
            .collect();
        assert!(
            send_steps.len() >= 2,
            "coordinator should have at least 2 send steps, got {}",
            send_steps.len()
        );
    }

    #[test]
    fn two_phase_commit_worker_saga_plan() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let worker = &output.participants["worker"];
        assert!(!worker.saga_plan.steps.is_empty());

        // Worker receives: reserve, commit/abort
        let recv_steps: Vec<_> = worker
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Recv)
            .collect();
        assert!(
            recv_steps.len() >= 2,
            "worker should have at least 2 recv steps, got {}",
            recv_steps.len()
        );
    }

    #[test]
    fn two_phase_commit_calm_batching() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        // Should have coordination barriers (commit/abort are non-monotone)
        assert!(
            coord.execution_plan.coordination_barrier_count() > 0
                || coord.execution_plan.coordination_free_batch_count() > 0,
            "execution plan should have at least one batch"
        );
    }

    // ------------------------------------------------------------------
    // Pipeline generation — lease renewal
    // ------------------------------------------------------------------

    #[test]
    fn generate_lease_renewal() {
        let protocol = example_lease_renewal();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert_eq!(output.protocol_name, "lease_renewal");
        assert!(output.participants.contains_key("holder"));
        assert!(output.participants.contains_key("resource"));
    }

    #[test]
    fn lease_renewal_holder_has_loop_steps() {
        let protocol = example_lease_renewal();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let holder = &output.participants["holder"];
        // Holder sends acquire, renew, release — at least 3 send steps
        let send_count = holder
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Send)
            .count();
        assert!(send_count >= 3, "holder should send acquire+renew+release");
    }

    // ------------------------------------------------------------------
    // Pipeline generation — saga compensation
    // ------------------------------------------------------------------

    #[test]
    fn generate_saga_compensation() {
        let protocol = example_saga_compensation();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert_eq!(output.protocol_name, "saga_with_compensation");
        assert_eq!(output.participants.len(), 3);
        assert!(output.participants.contains_key("coordinator"));
        assert!(output.participants.contains_key("service_a"));
        assert!(output.participants.contains_key("service_b"));
    }

    #[test]
    fn saga_compensation_has_compensation_steps() {
        let protocol = example_saga_compensation();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        // Compensation protocol should generate Reserve and Abort boundary steps
        let has_reserve = coord
            .saga_plan
            .steps
            .iter()
            .any(|s| s.op == SagaOpKind::Reserve);
        let has_abort = coord
            .saga_plan
            .steps
            .iter()
            .any(|s| s.op == SagaOpKind::Abort);
        assert!(
            has_reserve || has_abort,
            "compensation protocol should have reserve/abort boundary steps"
        );
    }

    #[test]
    fn compensate_keeps_compensation_only_participants_without_spurious_boundaries() {
        let protocol = GlobalProtocol::builder("compensation_partial_roles")
            .participant("coordinator", "saga-coordinator")
            .participant("worker", "saga-worker")
            .participant("undoer", "saga-undoer")
            .interaction(Interaction::compensate(
                Interaction::comm("coordinator", "reserve_work", "ReserveMsg", "worker"),
                Interaction::comm("coordinator", "undo_work", "UndoMsg", "undoer"),
            ))
            .build();

        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let worker = &output.participants["worker"];
        assert!(
            worker
                .saga_plan
                .steps
                .iter()
                .any(|s| s.label == "recv_reserve_work"),
            "forward-only participant should keep forward step"
        );
        assert!(
            !worker
                .saga_plan
                .steps
                .iter()
                .any(|s| s.label == "compensation_boundary" || s.label == "compensation_abort"),
            "forward-only participant should not get compensation boundary markers"
        );

        let undoer = &output.participants["undoer"];
        assert!(
            undoer
                .saga_plan
                .steps
                .iter()
                .any(|s| s.label == "recv_undo_work"),
            "compensation-only participant should keep compensation step"
        );
        assert!(
            !undoer
                .saga_plan
                .steps
                .iter()
                .any(|s| s.label == "compensation_boundary" || s.label == "compensation_abort"),
            "compensation-only participant should not get compensation boundary markers"
        );
    }

    // ------------------------------------------------------------------
    // Source code content
    // ------------------------------------------------------------------

    #[test]
    fn source_code_contains_cx_checkpoint() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            assert!(
                participant.source_code.contains("cx.checkpoint()"),
                "{name} source code should contain cx.checkpoint()"
            );
        }
    }

    #[test]
    fn source_code_contains_cx_trace() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            assert!(
                participant.source_code.contains("cx.trace("),
                "{name} source code should contain cx.trace()"
            );
        }
    }

    #[test]
    fn source_code_contains_evidence_emission() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            assert!(
                participant.source_code.contains("EvidenceLedgerBuilder"),
                "{name} source code should contain EvidenceLedgerBuilder"
            );
            assert!(
                participant.source_code.contains("cx.emit_evidence"),
                "{name} source code should contain cx.emit_evidence()"
            );
        }
    }

    #[test]
    fn source_code_contains_saga_plan_fn() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        assert!(
            coord
                .source_code
                .contains("pub fn two_phase_commit_coordinator_saga_plan()")
        );

        let worker = &output.participants["worker"];
        assert!(
            worker
                .source_code
                .contains("pub fn two_phase_commit_worker_saga_plan()")
        );
    }

    #[test]
    fn source_code_contains_do_not_edit() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for participant in output.participants.values() {
            assert!(participant.source_code.contains("DO NOT EDIT"));
        }
    }

    #[test]
    fn source_code_contains_session_type() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        assert!(coord.source_code.contains("coordinator_Session"));

        let worker = &output.participants["worker"];
        assert!(worker.source_code.contains("worker_Session"));
    }

    #[test]
    fn worker_source_uses_responder_entry_channel() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");
        let worker = &output.participants["worker"];

        assert!(
            worker
                .source_code
                .contains("chan: Chan<Responder, worker_Session>"),
            "worker should use responder polarity for its entry channel"
        );
        assert!(
            !worker
                .source_code
                .contains("chan: Chan<Initiator, worker_Session>"),
            "worker should not be rendered as an initiator"
        );
    }

    // ------------------------------------------------------------------
    // Lab test scaffold
    // ------------------------------------------------------------------

    #[test]
    fn lab_test_generated() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert!(
            !output.lab_test_code.is_empty(),
            "lab test code should be generated"
        );
        assert!(
            output
                .lab_test_code
                .contains("test_two_phase_commit_choreography")
        );
        assert!(
            output
                .lab_test_code
                .contains("test_two_phase_commit_calm_analysis")
        );
    }

    #[test]
    fn lab_test_disabled() {
        let protocol = example_two_phase_commit();
        let mut pipe = pipeline();
        pipe.generate_lab_tests = false;

        let output = pipe
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert!(
            output.lab_test_code.is_empty(),
            "lab test code should be empty when disabled"
        );
    }

    #[test]
    fn lab_test_contains_participant_spawns() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert!(output.lab_test_code.contains("_coordinator_task"));
        assert!(output.lab_test_code.contains("_worker_task"));
        assert!(
            output
                .lab_test_code
                .contains("LabRuntime::new(asupersync::LabConfig::default())")
        );
        // Ensure generated lab test uses asupersync runtime, not tokio
        let tokio_spawn = format!("{}::{}", "tokio", "spawn");
        assert!(!output.lab_test_code.contains(&tokio_spawn));
    }

    #[test]
    fn lab_test_channel_scaffold_is_unique_per_participant() {
        let protocol = example_scatter_gather_disjoint();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        // Pairwise directional lab channel stand-ins must exist.
        assert!(
            output
                .lab_test_code
                .contains("let (chan_proxy_a_to_proxy_b, chan_proxy_b_to_proxy_a) = (")
        );
        assert!(
            output
                .lab_test_code
                .contains("let (chan_proxy_a_to_worker_a, chan_worker_a_to_proxy_a) = (")
        );

        // Each participant should have exactly one entry-channel unit stand-in.
        for name in ["proxy_a", "proxy_b", "worker_a", "worker_b"] {
            let decl = format!("let chan_{name} = ();");
            assert_eq!(
                output.lab_test_code.matches(&decl).count(),
                1,
                "{name} should have exactly one channel entry unit stand-in"
            );
        }
    }

    // ------------------------------------------------------------------
    // plan_only
    // ------------------------------------------------------------------

    #[test]
    fn plan_only_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let (plan, exec) = pipeline()
            .plan_only(&protocol, "coordinator")
            .expect("plan_only failed");

        assert!(!plan.steps.is_empty());
        assert!(exec.total_steps() > 0);
    }

    #[test]
    fn plan_only_saga_compensation() {
        let protocol = example_saga_compensation();
        let (plan, exec) = pipeline()
            .plan_only(&protocol, "service_a")
            .expect("plan_only failed");

        assert!(!plan.steps.is_empty());
        assert!(exec.total_steps() > 0);
    }

    // ------------------------------------------------------------------
    // Error cases
    // ------------------------------------------------------------------

    #[test]
    fn pipeline_error_display() {
        let err = PipelineError::NoParticipants;
        assert_eq!(format!("{err}"), "no participants produced output");

        let err = PipelineError::Compilation(CompilationError::ParticipantNotFound {
            name: "x".to_string(),
        });
        assert!(format!("{err}").contains("participant 'x'"));
    }

    // ------------------------------------------------------------------
    // All example protocols through the pipeline
    // ------------------------------------------------------------------

    #[test]
    fn all_example_protocols_through_pipeline() {
        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
        ];

        let pipe = pipeline();
        for protocol in &protocols {
            let output = pipe
                .generate_with_locals(protocol)
                .unwrap_or_else(|_| panic!("pipeline failed for {}", protocol.name));

            assert!(
                !output.participants.is_empty(),
                "no participants for {}",
                protocol.name
            );

            for (name, participant) in &output.participants {
                // Every participant should have non-empty saga plan
                assert!(
                    !participant.saga_plan.steps.is_empty(),
                    "{name} in {} has empty saga plan",
                    protocol.name
                );

                // Every participant should have non-empty source code
                assert!(
                    !participant.source_code.is_empty(),
                    "{name} in {} has empty source code",
                    protocol.name
                );

                // Source code should reference key integrations
                assert!(
                    participant.source_code.contains("cx.checkpoint()"),
                    "{name} in {} missing cx.checkpoint()",
                    protocol.name
                );
                assert!(
                    participant.source_code.contains("chan."),
                    "{name} in {} missing session channel operations",
                    protocol.name
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // CALM monotonicity properties
    // ------------------------------------------------------------------

    #[test]
    fn monotone_ratio_reasonable() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            let ratio = participant.saga_plan.monotone_ratio();
            assert!(
                (0.0..=1.0).contains(&ratio),
                "{name} has invalid monotone ratio: {ratio}"
            );
        }
    }

    #[test]
    fn execution_plan_step_count_matches_saga_plan() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            assert_eq!(
                participant.execution_plan.total_steps(),
                participant.saga_plan.steps.len(),
                "{name}: execution plan steps != saga plan steps"
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: scatter-gather disjoint through full pipeline (bd-1f8jn.4 item 5)
    // ------------------------------------------------------------------

    #[test]
    fn generate_scatter_gather_disjoint() {
        let protocol = example_scatter_gather_disjoint();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert_eq!(output.protocol_name, "scatter_gather_disjoint");
        assert_eq!(output.participants.len(), 4);
        assert!(output.participants.contains_key("proxy_a"));
        assert!(output.participants.contains_key("proxy_b"));
        assert!(output.participants.contains_key("worker_a"));
        assert!(output.participants.contains_key("worker_b"));
    }

    #[test]
    fn scatter_gather_proxy_sends_and_worker_receives() {
        let protocol = example_scatter_gather_disjoint();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let proxy_a = &output.participants["proxy_a"];
        let worker_a = &output.participants["worker_a"];

        // proxy_a sends request_a, receives response_a
        let proxy_send_count = proxy_a
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Send)
            .count();
        let proxy_recv_count = proxy_a
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Recv)
            .count();
        assert_eq!(proxy_send_count, 1, "proxy_a should send once");
        assert_eq!(proxy_recv_count, 1, "proxy_a should recv once");

        // worker_a receives request_a, sends response_a
        let worker_send_count = worker_a
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Send)
            .count();
        let worker_recv_count = worker_a
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Recv)
            .count();
        assert_eq!(worker_send_count, 1, "worker_a should send once");
        assert_eq!(worker_recv_count, 1, "worker_a should recv once");
    }

    #[test]
    fn scatter_gather_lab_test_references_all_participants() {
        let protocol = example_scatter_gather_disjoint();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert!(output.lab_test_code.contains("_proxy_a_task"));
        assert!(output.lab_test_code.contains("_proxy_b_task"));
        assert!(output.lab_test_code.contains("_worker_a_task"));
        assert!(output.lab_test_code.contains("_worker_b_task"));
    }

    // ------------------------------------------------------------------
    // E2E: codegen determinism (bd-1f8jn.4 item 8)
    // ------------------------------------------------------------------

    #[test]
    fn codegen_deterministic_across_runs() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let pipe = pipeline();

        for protocol in &protocols {
            let output1 = pipe
                .generate_with_locals(protocol)
                .expect("pipeline failed");
            let output2 = pipe
                .generate_with_locals(protocol)
                .expect("pipeline failed");

            // Same participants
            assert_eq!(
                output1.participants.len(),
                output2.participants.len(),
                "{}: participant count differs across runs",
                protocol.name
            );

            // Same source code for each participant
            for (name, p1) in &output1.participants {
                let p2 = &output2.participants[name];
                assert_eq!(
                    p1.source_code, p2.source_code,
                    "{}: source code differs for {name}",
                    protocol.name
                );

                // Hash-based golden check
                let mut h1 = DetHasher::default();
                p1.source_code.hash(&mut h1);
                let mut h2 = DetHasher::default();
                p2.source_code.hash(&mut h2);
                assert_eq!(
                    h1.finish(),
                    h2.finish(),
                    "{}: code hash differs for {name}",
                    protocol.name
                );
            }

            // Same lab test code
            assert_eq!(
                output1.lab_test_code, output2.lab_test_code,
                "{}: lab test code differs",
                protocol.name
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: cross-protocol structural invariants (bd-1f8jn.4 item 5)
    // ------------------------------------------------------------------

    #[test]
    fn all_valid_protocols_through_full_pipeline() {
        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let pipe = pipeline();
        for protocol in &protocols {
            let output = pipe
                .generate_with_locals(protocol)
                .unwrap_or_else(|e| panic!("{}: pipeline failed: {e}", protocol.name));

            // Structural invariants every output must satisfy:
            assert!(
                !output.participants.is_empty(),
                "{}: no participants",
                protocol.name
            );

            for (name, p) in &output.participants {
                // Protocol metadata consistency
                assert_eq!(
                    p.protocol_name, protocol.name,
                    "{name}: protocol_name mismatch"
                );
                assert_eq!(
                    p.participant_name, *name,
                    "{name}: participant_name mismatch"
                );

                // Saga plan non-empty
                assert!(
                    !p.saga_plan.steps.is_empty(),
                    "{name} in {}: empty saga plan",
                    protocol.name
                );

                // Execution plan covers all steps
                assert_eq!(
                    p.execution_plan.total_steps(),
                    p.saga_plan.steps.len(),
                    "{name} in {}: step count mismatch",
                    protocol.name
                );

                // Monotone ratio valid
                let ratio = p.saga_plan.monotone_ratio();
                assert!(
                    (0.0..=1.0).contains(&ratio),
                    "{name} in {}: invalid monotone ratio {ratio}",
                    protocol.name
                );

                // Source code structural requirements
                assert!(
                    p.source_code.contains("cx.checkpoint()"),
                    "{name} in {}: missing cx.checkpoint()",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("cx.trace("),
                    "{name} in {}: missing cx.trace()",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("EvidenceLedgerBuilder"),
                    "{name} in {}: missing EvidenceLedgerBuilder",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("DO NOT EDIT"),
                    "{name} in {}: missing DO NOT EDIT header",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("use asupersync::cx::Cx;"),
                    "{name} in {}: missing Cx import",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("pub async fn"),
                    "{name} in {}: missing async handler",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("pub fn")
                        && p.source_code.contains("_saga_plan() -> SagaPlan"),
                    "{name} in {}: missing saga_plan constructor",
                    protocol.name
                );
            }

            // Lab test scaffold present
            assert!(
                !output.lab_test_code.is_empty(),
                "{}: empty lab test code",
                protocol.name
            );
            assert!(
                output.lab_test_code.contains("#[cfg(test)]"),
                "{}: lab test missing cfg(test)",
                protocol.name
            );
            assert!(
                output
                    .lab_test_code
                    .contains("LabRuntime::new(asupersync::LabConfig::default())"),
                "{}: lab test missing LabRuntime scaffold",
                protocol.name
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: plan_only consistency with generate (bd-1f8jn.4)
    // ------------------------------------------------------------------

    #[test]
    fn plan_only_matches_generate_saga_plan() {
        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let pipe = pipeline();
        for protocol in &protocols {
            let output = pipe
                .generate_with_locals(protocol)
                .unwrap_or_else(|e| panic!("{}: generate failed: {e}", protocol.name));

            for (name, p) in &output.participants {
                let (plan, exec) = pipe.plan_only(protocol, name).unwrap_or_else(|e| {
                    panic!("{}: plan_only failed for {name}: {e}", protocol.name)
                });

                // Same step count
                assert_eq!(
                    plan.steps.len(),
                    p.saga_plan.steps.len(),
                    "{name} in {}: plan_only step count differs from generate",
                    protocol.name
                );

                // Same step labels and ops
                for (i, (a, b)) in plan.steps.iter().zip(p.saga_plan.steps.iter()).enumerate() {
                    assert_eq!(
                        a.op, b.op,
                        "{name} in {} step {i}: op mismatch ({:?} vs {:?})",
                        protocol.name, a.op, b.op
                    );
                    assert_eq!(
                        a.label, b.label,
                        "{name} in {} step {i}: label mismatch",
                        protocol.name
                    );
                }

                // Same execution plan totals
                assert_eq!(
                    exec.total_steps(),
                    p.execution_plan.total_steps(),
                    "{name} in {}: execution plan total_steps mismatch",
                    protocol.name
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // E2E: compensation boundary markers (bd-1f8jn.4 item 5)
    // ------------------------------------------------------------------

    #[test]
    fn saga_compensation_source_code_has_compensation_scope() {
        let protocol = example_saga_compensation();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        // At least one participant should have compensation scope in generated code
        let has_compensation = output.participants.values().any(|p| {
            p.source_code.contains("compensation")
                || p.source_code.contains("Compensation")
                || p.source_code.contains("rollback")
        });
        assert!(
            has_compensation,
            "saga compensation protocol should generate compensation scope code"
        );
    }

    #[test]
    fn saga_compensation_all_participants_have_steps() {
        let protocol = example_saga_compensation();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, p) in &output.participants {
            assert!(
                !p.saga_plan.steps.is_empty(),
                "{name} has empty saga plan in compensation protocol"
            );
            assert!(
                !p.source_code.is_empty(),
                "{name} has empty source code in compensation protocol"
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: CALM batch analysis across protocols (bd-1f8jn.4 item 5)
    // ------------------------------------------------------------------

    #[test]
    fn calm_batching_produces_at_least_one_batch_per_participant() {
        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let pipe = pipeline();
        for protocol in &protocols {
            let output = pipe
                .generate_with_locals(protocol)
                .unwrap_or_else(|e| panic!("{}: pipeline failed: {e}", protocol.name));

            for (name, p) in &output.participants {
                let batch_count = p.execution_plan.coordination_free_batch_count()
                    + p.execution_plan.coordination_barrier_count();
                assert!(
                    batch_count > 0,
                    "{name} in {}: no CALM batches",
                    protocol.name
                );
            }
        }
    }

    #[test]
    fn source_code_calm_header_reflects_batch_counts() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for p in output.participants.values() {
            // Header should contain CALM batch info
            assert!(
                p.source_code.contains("CALM batches:"),
                "source code missing CALM batch header"
            );
            assert!(
                p.source_code.contains("Monotone ratio:"),
                "source code missing monotone ratio header"
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: pipeline error paths (bd-1f8jn.4)
    // ------------------------------------------------------------------

    #[test]
    fn pipeline_rejects_invalid_protocol() {
        use crate::obligation::choreography::Interaction;

        // Protocol with self-communication (invalid)
        let protocol = GlobalProtocol::builder("bad_protocol")
            .participant("alice", "role")
            .interaction(Interaction::comm("alice", "msg", "Msg", "alice"))
            .build();

        let result = pipeline().generate_with_locals(&protocol);
        assert!(result.is_err(), "pipeline should reject invalid protocol");

        match result.unwrap_err() {
            PipelineError::Compilation(CompilationError::ValidationFailed(errors)) => {
                assert!(!errors.is_empty());
            }
            other => panic!("expected ValidationFailed, got: {other}"),
        }
    }

    #[test]
    fn plan_only_rejects_invalid_protocol() {
        use crate::obligation::choreography::Interaction;

        let protocol = GlobalProtocol::builder("bad_protocol")
            .participant("alice", "role")
            .interaction(Interaction::comm("alice", "msg", "Msg", "alice"))
            .build();

        let result = pipeline().plan_only(&protocol, "alice");
        assert!(result.is_err(), "plan_only should reject invalid protocol");
    }
