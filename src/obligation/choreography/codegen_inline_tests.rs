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
        example_lease_renewal, example_saga_compensation, example_two_phase_commit,
    };

    fn compiler() -> ProjectionCompiler {
        ProjectionCompiler::new()
    }

    // ------------------------------------------------------------------
    // Basic compilation
    // ------------------------------------------------------------------

    #[test]
    fn compile_two_phase_commit_coordinator() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");

        assert_eq!(output.protocol_name, "two_phase_commit");
        assert_eq!(output.participant_name, "coordinator");
        assert_eq!(output.participant_role, "saga-coordinator");
        assert!(output.local_state_count > 0);
        assert!(output.local_transition_count > 0);
    }

    #[test]
    fn compile_two_phase_commit_worker() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "worker")
            .expect("compilation failed");

        assert_eq!(output.participant_name, "worker");
        assert_eq!(output.participant_role, "saga-participant");
    }

    #[test]
    fn compile_all_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let outputs = compiler()
            .compile_all(&protocol)
            .expect("compilation failed");

        assert_eq!(outputs.len(), 2);
        assert!(outputs.contains_key("coordinator"));
        assert!(outputs.contains_key("worker"));
    }

    #[test]
    fn compile_lease_renewal() {
        let protocol = example_lease_renewal();
        let output = compiler()
            .compile(&protocol, "holder")
            .expect("compilation failed");

        assert_eq!(output.protocol_name, "lease_renewal");
        // Should have 3 messages: Acquire, Renew, Release
        assert_eq!(output.message_structs.len(), 3);
    }

    #[test]
    fn compile_saga_compensation() {
        let protocol = example_saga_compensation();
        let outputs = compiler()
            .compile_all(&protocol)
            .expect("compilation failed");

        assert_eq!(outputs.len(), 3);
        assert!(outputs.contains_key("coordinator"));
        assert!(outputs.contains_key("service_a"));
        assert!(outputs.contains_key("service_b"));
    }

    // ------------------------------------------------------------------
    // Session type generation
    // ------------------------------------------------------------------

    #[test]
    fn session_type_two_phase_commit_coordinator() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");

        // coordinator: Send<Reserve, Select<Send<Commit, End>, Send<Abort, End>>>
        assert!(output.session_type.contains("Send<ReserveMsg"));
        assert!(output.session_type.contains("Select<"));
        assert!(output.session_type.contains("CommitMsg"));
        assert!(output.session_type.contains("AbortMsg"));
    }

    #[test]
    fn session_type_two_phase_commit_worker() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "worker")
            .expect("compilation failed");

        // worker: Recv<Reserve, Offer<Recv<Commit, End>, Recv<Abort, End>>>
        assert!(output.session_type.contains("Recv<ReserveMsg"));
        assert!(output.session_type.contains("Offer<"));
    }

    // ------------------------------------------------------------------
    // Code generation
    // ------------------------------------------------------------------

    #[test]
    fn generated_code_contains_protocol_header() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("Protocol: two_phase_commit"));
        assert!(code.contains("Participant: coordinator"));
        assert!(code.contains("DO NOT EDIT"));
    }

    #[test]
    fn generated_code_contains_message_structs() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("pub struct ReserveMsg"));
        assert!(code.contains("pub struct CommitMsg"));
        assert!(code.contains("pub struct AbortMsg"));
    }

    #[test]
    fn generated_code_contains_handler_function() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("pub async fn two_phase_commit_coordinator"));
        assert!(code.contains("chan.send("));
        assert!(code.contains("chan.select_left()"));
        assert!(code.contains("chan.close()"));
    }

    #[test]
    fn generated_handler_uses_responder_channel_for_receiver_projection() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "worker")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("chan: Chan<Responder, worker_Session>"));
        assert!(!code.contains("chan: Chan<Initiator, worker_Session>"));
    }

    #[test]
    fn generated_code_worker_has_offer() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "worker")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("chan.recv()"));
        assert!(code.contains("chan.offer()"));
        assert!(code.contains("Left(chan)"));
        assert!(code.contains("Right(chan)"));
    }

    #[test]
    fn generated_code_lease_has_loop() {
        let protocol = example_lease_renewal();
        let output = compiler()
            .compile(&protocol, "holder")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("loop {"));
        assert!(code.contains("continue;"));
        assert!(code.contains("break;"));
    }

    #[test]
    fn generated_code_compensation_block() {
        let protocol = example_saga_compensation();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("Compensation block"));
        assert!(code.contains("Forward:"));
        assert!(code.contains("Compensation (on failure):"));
    }

    #[test]
    fn generated_code_compensation_actions_are_commented_skeletons() {
        let protocol = example_saga_compensation();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        let mut found_compensate_send = false;
        for line in code.lines() {
            if line.contains("let chan = chan.send(CompensateMsg") {
                found_compensate_send = true;
                assert!(
                    line.trim_start().starts_with("//"),
                    "Compensation send must be commented skeleton code, got: {line}"
                );
            }
        }
        assert!(
            found_compensate_send,
            "Expected generated compensation skeleton to include CompensateMsg send skeleton"
        );
    }

    // ------------------------------------------------------------------
    // CALM annotations
    // ------------------------------------------------------------------

    #[test]
    fn calm_annotations_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");

        // coordinator: reserve (monotone send), commit (non-monotone send), abort (non-monotone send)
        assert_eq!(output.calm_annotations.len(), 3);

        let reserve = output
            .calm_annotations
            .iter()
            .find(|a| a.action == "reserve")
            .expect("reserve annotation missing");
        assert_eq!(reserve.monotonicity, Monotonicity::Monotone);
        assert_eq!(reserve.direction, "send");

        let commit = output
            .calm_annotations
            .iter()
            .find(|a| a.action == "commit")
            .expect("commit annotation missing");
        assert_eq!(commit.monotonicity, Monotonicity::NonMonotone);
    }

    // ------------------------------------------------------------------
    // Error cases
    // ------------------------------------------------------------------

    #[test]
    fn compile_unknown_participant() {
        let protocol = example_two_phase_commit();
        let result = compiler().compile(&protocol, "unknown");

        assert!(matches!(
            result,
            Err(CompilationError::ParticipantNotFound { .. })
        ));
    }

    #[test]
    fn compile_invalid_protocol() {
        let protocol = GlobalProtocol::builder("bad")
            .interaction(Interaction::end())
            .build();

        let result = compiler().compile(&protocol, "nobody");
        assert!(matches!(result, Err(CompilationError::ValidationFailed(_))));
    }

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------

    #[test]
    fn summary_format() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");

        let summary = output.summary();
        assert!(summary.contains("two_phase_commit"));
        assert!(summary.contains("coordinator"));
        assert!(summary.contains("saga-coordinator"));
    }

    // ------------------------------------------------------------------
    // Render completeness
    // ------------------------------------------------------------------

    #[test]
    fn render_all_five_examples() {
        use crate::obligation::choreography::*;

        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let c = compiler();
        for protocol in &protocols {
            let outputs = c.compile_all(protocol).expect("compilation failed");
            assert!(!outputs.is_empty(), "No outputs for {}", protocol.name);
            for (name, output) in &outputs {
                let code = output.render();
                assert!(!code.is_empty(), "Empty code for {name}");
                assert!(
                    code.contains("chan.close()"),
                    "Missing close for {name} in {}",
                    protocol.name
                );
            }
        }
    }

    // ==================================================================
    // bd-1f8jn.4: Comprehensive codegen test suite
    // ==================================================================

    // ------------------------------------------------------------------
    // Codegen determinism
    // ------------------------------------------------------------------

    #[test]
    fn codegen_deterministic_two_phase_commit() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let out1 = c.compile(&protocol, "coordinator").unwrap();
        let out2 = c.compile(&protocol, "coordinator").unwrap();
        assert_eq!(out1.render(), out2.render());
        assert_eq!(out1.session_type, out2.session_type);
    }

    #[test]
    fn codegen_deterministic_all_participants() {
        let c = compiler();
        let protocol = example_saga_compensation();
        let all1 = c.compile_all(&protocol).unwrap();
        let all2 = c.compile_all(&protocol).unwrap();
        assert_eq!(all1.len(), all2.len());
        for (name, o1) in &all1 {
            let o2 = &all2[name];
            assert_eq!(
                o1.render(),
                o2.render(),
                "Non-deterministic codegen for {name}"
            );
            assert_eq!(o1.session_type, o2.session_type);
        }
    }

    // ------------------------------------------------------------------
    // Message struct collection
    // ------------------------------------------------------------------

    #[test]
    fn message_structs_no_duplicates() {
        let c = compiler();
        let protocol = example_saga_compensation();
        let output = c.compile(&protocol, "coordinator").unwrap();
        let names: Vec<&str> = output
            .message_structs
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "Duplicate messages: {names:?}");
    }

    #[test]
    fn message_structs_match_protocol_comms() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let coord = c.compile(&protocol, "coordinator").unwrap();
        let msg_names: BTreeSet<&str> = coord
            .message_structs
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert!(msg_names.contains("ReserveMsg"));
        assert!(msg_names.contains("CommitMsg"));
        assert!(msg_names.contains("AbortMsg"));
    }

    #[test]
    fn message_structs_only_relevant_to_participant() {
        let c = compiler();
        let protocol = example_saga_compensation();
        let sa = c.compile(&protocol, "service_a").unwrap();
        let msg_names: BTreeSet<&str> =
            sa.message_structs.iter().map(|m| m.name.as_str()).collect();
        assert!(msg_names.contains("ReserveMsg"));
        assert!(msg_names.contains("CommitMsg"));
        assert!(msg_names.contains("AbortMsg"));
        assert!(msg_names.contains("CompensateMsg"));
    }

    // ------------------------------------------------------------------
    // Session type structure
    // ------------------------------------------------------------------

    #[test]
    fn session_type_lease_has_recursion() {
        let c = compiler();
        let protocol = example_lease_renewal();
        let output = c.compile(&protocol, "holder").unwrap();
        assert!(
            output.session_type.contains("Rec_renew_loop"),
            "Expected recursion, got: {}",
            output.session_type
        );
    }

    #[test]
    fn session_type_end_at_leaves() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        assert!(output.session_type.contains("End"));
    }

    // ------------------------------------------------------------------
    // CALM annotation correctness
    // ------------------------------------------------------------------

    #[test]
    fn calm_annotations_worker_perspective() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "worker").unwrap();
        assert_eq!(output.calm_annotations.len(), 3);
        for ann in &output.calm_annotations {
            assert_eq!(ann.direction, "recv");
            assert_eq!(ann.peer, "coordinator");
        }
    }

    #[test]
    fn calm_annotations_missing_when_no_calm_tags() {
        let protocol = GlobalProtocol::builder("no_calm")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(
                Interaction::comm("a", "msg", "Msg", "b")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
            )
            .build();
        let c = compiler();
        let output = c.compile(&protocol, "a").unwrap();
        assert!(output.calm_annotations.is_empty());
    }

    // ------------------------------------------------------------------
    // Complexity counting
    // ------------------------------------------------------------------

    #[test]
    fn complexity_two_phase_commit_coordinator() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        assert!(output.local_state_count > 0);
        assert!(output.local_transition_count > 0);
        assert!(output.local_transition_count <= output.local_state_count * 2);
    }

    #[test]
    fn complexity_grows_with_protocol_size() {
        let c = compiler();
        let simple = example_two_phase_commit();
        let complex = example_saga_compensation();
        let simple_out = c.compile(&simple, "coordinator").unwrap();
        let complex_out = c.compile(&complex, "coordinator").unwrap();
        assert!(complex_out.local_state_count >= simple_out.local_state_count);
    }

    // ------------------------------------------------------------------
    // Generated code structure
    // ------------------------------------------------------------------

    #[test]
    fn generated_code_has_imports() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        let code = output.render();
        assert!(code.contains("use asupersync::obligation::session_types::"));
        assert!(code.contains("Chan, End, Send, Recv"));
    }

    #[test]
    fn generated_code_tracing_disabled() {
        let c = ProjectionCompiler {
            include_tracing: false,
        };
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        let code = output.render();
        assert!(!code.contains("Span:"));
    }

    #[test]
    fn generated_code_tracing_enabled() {
        let c = ProjectionCompiler {
            include_tracing: true,
        };
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        let code = output.render();
        assert!(code.contains("Span:"));
    }

    #[test]
    fn compilation_error_display() {
        let err1 = CompilationError::ParticipantNotFound { name: "x".into() };
        assert!(format!("{err1}").contains("'x'"));

        let err2 = CompilationError::EmptyProjection {
            participant: "y".into(),
        };
        assert!(format!("{err2}").contains("'y'"));

        let err3 =
            CompilationError::ValidationFailed(vec![super::super::ValidationError::EmptyProtocol]);
        assert!(format!("{err3}").contains("validation failed"));
    }

    // ------------------------------------------------------------------
    // compile_all skips uninvolved participants
    // ------------------------------------------------------------------

    #[test]
    fn compile_all_skips_uninvolved() {
        let protocol = GlobalProtocol::builder("partial")
            .participant("a", "role")
            .participant("b", "role")
            .participant("ghost", "role")
            .interaction(
                Interaction::comm("a", "msg", "Msg", "b")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
            )
            .build();

        let c = compiler();
        let outputs = c.compile_all(&protocol).unwrap();
        assert!(outputs.contains_key("a"));
        assert!(outputs.contains_key("b"));
        assert!(!outputs.contains_key("ghost"));
    }

    #[test]
    fn generated_message_debug_clone_eq() {
        let msg = GeneratedMessage {
            name: "Ping".to_string(),
            has_payload: true,
            type_params: vec!["T".to_string()],
        };
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
        assert_ne!(
            msg,
            GeneratedMessage {
                name: "Pong".to_string(),
                has_payload: false,
                type_params: vec![],
            }
        );
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("GeneratedMessage"));
        assert!(dbg.contains("Ping"));
    }

    #[test]
    fn compilation_error_debug_clone() {
        let err = CompilationError::ParticipantNotFound {
            name: "ghost".to_string(),
        };
        let cloned = err.clone();
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ParticipantNotFound"));
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    // =========================================================================
    // Codegen determinism metamorphic relations.
    //
    // Oracle problem: the "correct" generated Rust code is defined by the
    // codegen algorithm itself. We cannot independently compute expected
    // output. But we CAN pin relations:
    //   - Same input → byte-identical output (determinism)
    //   - compile_all(p)[pn] == compile(p, pn) (single/batch agreement)
    //   - Fresh compiler instances with same config → identical output
    //   - Validation errors are deterministic too
    //
    // Per-case determinism tests exist for two fixed protocols
    // (codegen_deterministic_two_phase_commit + _all_participants). These
    // MRs bind the full determinism contract across every bundled example.
    // =========================================================================

    mod codegen_determinism_mr {
        use super::*;

        fn all_examples() -> Vec<(&'static str, GlobalProtocol)> {
            vec![
                ("two_phase_commit", example_two_phase_commit()),
                ("saga_compensation", example_saga_compensation()),
                ("lease_renewal", example_lease_renewal()),
            ]
        }

        /// MR — Byte-exact determinism across all bundled examples.
        /// Running compile() N times on the same (protocol, participant)
        /// must produce byte-identical session_type, handler_skeleton, and
        /// render() output. Covers every participant in every example.
        #[test]
        fn mr_codegen_byte_exact_determinism_across_examples() {
            let c = compiler();
            for (label, protocol) in all_examples() {
                for participant_name in protocol.participants.keys() {
                    let out_a = c
                        .compile(&protocol, participant_name)
                        .unwrap_or_else(|e| panic!("{label}/{participant_name}: {e:?}"));
                    let out_b = c
                        .compile(&protocol, participant_name)
                        .unwrap_or_else(|e| panic!("{label}/{participant_name}: {e:?}"));
                    assert_eq!(
                        out_a.render(),
                        out_b.render(),
                        "render() diverged on repeat compile for {label}/{participant_name}",
                    );
                    assert_eq!(out_a.session_type, out_b.session_type);
                    assert_eq!(out_a.handler_skeleton, out_b.handler_skeleton);
                    assert_eq!(out_a.message_structs, out_b.message_structs);
                    assert_eq!(
                        format!("{:?}", out_a.calm_annotations),
                        format!("{:?}", out_b.calm_annotations),
                    );
                    assert_eq!(out_a.local_state_count, out_b.local_state_count);
                    assert_eq!(out_a.local_transition_count, out_b.local_transition_count);
                }
            }
        }

        /// MR — Single/batch API agreement: compile_all(p)[pn] equals
        /// compile(p, pn) for every participant. The batch API must not
        /// diverge from the single-participant API.
        #[test]
        fn mr_codegen_compile_all_agrees_with_single() {
            let c = compiler();
            for (label, protocol) in all_examples() {
                let all = c
                    .compile_all(&protocol)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                for participant_name in protocol.participants.keys() {
                    let single = c
                        .compile(&protocol, participant_name)
                        .unwrap_or_else(|e| panic!("{label}/{participant_name}: {e:?}"));
                    let batch = all.get(participant_name).unwrap_or_else(|| {
                        panic!("{label}: compile_all missing participant {participant_name}")
                    });
                    assert_eq!(
                        single.render(),
                        batch.render(),
                        "single/batch rendering diverged for {label}/{participant_name}",
                    );
                    assert_eq!(single.session_type, batch.session_type);
                }
            }
        }

        /// MR — Compiler-instance independence: two fresh ProjectionCompiler
        /// instances with the same config produce byte-identical output on
        /// the same input. Rejects any hidden per-instance state or
        /// construction-time seeding.
        #[test]
        fn mr_codegen_fresh_instance_equals_reused_instance() {
            for (label, protocol) in all_examples() {
                for participant_name in protocol.participants.keys() {
                    let reused = compiler();
                    let fresh_1 = ProjectionCompiler::new();
                    let fresh_2 = ProjectionCompiler::new();
                    let a = reused.compile(&protocol, participant_name).unwrap();
                    let b = fresh_1.compile(&protocol, participant_name).unwrap();
                    let c = fresh_2.compile(&protocol, participant_name).unwrap();
                    assert_eq!(
                        a.render(),
                        b.render(),
                        "{label}/{participant_name}: reused vs fresh diverged"
                    );
                    assert_eq!(
                        b.render(),
                        c.render(),
                        "{label}/{participant_name}: two fresh instances diverged"
                    );
                }
            }
        }

        /// MR — Tracing-flag monotonicity: the same compiler config produces
        /// the same output across invocations; toggling tracing does NOT
        /// change anything other than the generated handler skeleton's
        /// tracing sites. Session type, message structs, CALM annotations,
        /// and complexity counts are identical with and without tracing.
        #[test]
        fn mr_codegen_tracing_flag_affects_only_handler() {
            let with_tracing = ProjectionCompiler {
                include_tracing: true,
            };
            let without = ProjectionCompiler {
                include_tracing: false,
            };
            for (label, protocol) in all_examples() {
                for participant_name in protocol.participants.keys() {
                    let a = with_tracing.compile(&protocol, participant_name).unwrap();
                    let b = without.compile(&protocol, participant_name).unwrap();
                    // Invariant surface: independent of tracing.
                    assert_eq!(
                        a.session_type, b.session_type,
                        "{label}/{participant_name}: session_type depends on tracing flag",
                    );
                    assert_eq!(
                        a.message_structs, b.message_structs,
                        "{label}/{participant_name}: message_structs depend on tracing flag",
                    );
                    assert_eq!(
                        format!("{:?}", a.calm_annotations),
                        format!("{:?}", b.calm_annotations),
                        "{label}/{participant_name}: calm_annotations depend on tracing flag",
                    );
                    assert_eq!(
                        a.local_state_count, b.local_state_count,
                        "{label}/{participant_name}: state_count depends on tracing flag",
                    );
                    assert_eq!(
                        a.local_transition_count, b.local_transition_count,
                        "{label}/{participant_name}: transition_count depends on tracing flag",
                    );
                }
            }
        }

        /// MR — compile_all key stability: compile_all(p) returns keys that
        /// are exactly protocol.participants' keys, independent of any
        /// iteration order the implementation might use internally.
        #[test]
        fn mr_codegen_compile_all_keys_match_participants() {
            let c = compiler();
            for (label, protocol) in all_examples() {
                let all = c.compile_all(&protocol).unwrap();
                let expected_keys: std::collections::BTreeSet<&str> =
                    protocol.participants.keys().map(String::as_str).collect();
                let got_keys: std::collections::BTreeSet<&str> =
                    all.keys().map(String::as_str).collect();
                assert_eq!(
                    got_keys, expected_keys,
                    "{label}: compile_all keys diverge from protocol.participants",
                );
            }
        }

        /// MR — Error determinism: requesting an unknown participant twice
        /// yields equivalent CompilationError::ParticipantNotFound values.
        /// A refactor that swapped BTreeMap → HashMap could make the error
        /// message nondeterministic; this pins it.
        #[test]
        fn mr_codegen_unknown_participant_error_is_deterministic() {
            let c = compiler();
            let (_, protocol) = all_examples().into_iter().next().unwrap();
            let e1 = c
                .compile(&protocol, "this-participant-does-not-exist")
                .expect_err("should fail");
            let e2 = c
                .compile(&protocol, "this-participant-does-not-exist")
                .expect_err("should fail");
            assert_eq!(format!("{e1:?}"), format!("{e2:?}"));
            match (&e1, &e2) {
                (
                    CompilationError::ParticipantNotFound { name: n1 },
                    CompilationError::ParticipantNotFound { name: n2 },
                ) => assert_eq!(n1, n2),
                _ => panic!("expected ParticipantNotFound twice, got {e1:?} / {e2:?}"),
            }
        }

        /// MR — Composite: determinism × batch-agreement. Calling
        /// compile_all twice and comparing per-participant render() is
        /// equivalent to pairing individual compile() calls — any mismatch
        /// localizes to which participant's rendering drifted.
        #[test]
        fn mr_codegen_composite_compile_all_twice_matches_single_twice() {
            let c = compiler();
            for (label, protocol) in all_examples() {
                let all_a = c.compile_all(&protocol).unwrap();
                let all_b = c.compile_all(&protocol).unwrap();
                for (participant_name, out_a) in &all_a {
                    let out_b = all_b
                        .get(participant_name)
                        .unwrap_or_else(|| panic!("{label}: missing {participant_name}"));
                    let single = c.compile(&protocol, participant_name).unwrap();
                    // Triangle: compile_all#1 == compile_all#2 == single.
                    assert_eq!(out_a.render(), out_b.render());
                    assert_eq!(out_a.render(), single.render());
                }
            }
        }
    }
