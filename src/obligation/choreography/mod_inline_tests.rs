    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // ------------------------------------------------------------------
    // Validation: well-formed protocols
    // ------------------------------------------------------------------

    #[test]
    fn two_phase_commit_validates() {
        let protocol = example_two_phase_commit();
        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
    }

    #[test]
    fn two_phase_commit_is_deadlock_free() {
        let protocol = example_two_phase_commit();
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn lease_renewal_validates() {
        let protocol = example_lease_renewal();
        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
    }

    #[test]
    fn lease_renewal_is_deadlock_free() {
        let protocol = example_lease_renewal();
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn saga_compensation_validates() {
        let protocol = example_saga_compensation();
        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
    }

    #[test]
    fn saga_compensation_is_deadlock_free() {
        let protocol = example_saga_compensation();
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn scatter_gather_disjoint_validates() {
        let protocol = example_scatter_gather_disjoint();
        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
    }

    // ------------------------------------------------------------------
    // Validation: error detection
    // ------------------------------------------------------------------

    #[test]
    fn detects_self_communication() {
        let protocol = GlobalProtocol::builder("bad")
            .participant("alice", "role")
            .interaction(
                Interaction::comm("alice", "ping", "Ping", "alice")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
            )
            .build();

        let errors = protocol.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::SelfCommunication { .. }))
        );
        assert!(!protocol.is_deadlock_free());
    }

    #[test]
    fn detects_undeclared_participant() {
        let protocol = GlobalProtocol::builder("bad")
            .participant("alice", "role")
            .interaction(
                Interaction::comm("alice", "ping", "Ping", "bob")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
            )
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(
            |e| matches!(e, ValidationError::UndeclaredParticipant { name, .. } if name == "bob")
        ));
        assert!(!protocol.is_deadlock_free());
    }

    #[test]
    fn detects_duplicate_participant_declaration() {
        let protocol = GlobalProtocol::builder("dupe_participant")
            .participant("alice", "role-v1")
            .participant("alice", "role-v2")
            .participant("bob", "role")
            .interaction(
                Interaction::comm("alice", "ping", "Ping", "bob")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
            )
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(
            |e| matches!(e, ValidationError::DuplicateParticipant { name } if name == "alice")
        ));
    }

    #[test]
    fn detects_knowledge_of_choice_violation() {
        // bob decides but alice sends first in the then-branch
        let protocol = GlobalProtocol::builder("bad")
            .participant("alice", "role-a")
            .participant("bob", "role-b")
            .interaction(Interaction::choice(
                "bob",
                "some_pred",
                // then-branch: alice sends first — violation!
                Interaction::comm("alice", "msg", "Msg", "bob")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
                // else-branch: bob sends — ok
                Interaction::comm("bob", "msg", "Msg", "alice")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
            ))
            .build();

        let errors = protocol.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::KnowledgeOfChoice { branch: "then", .. }))
        );
        assert!(!protocol.is_deadlock_free());
    }

    #[test]
    fn detects_undefined_loop_label() {
        let protocol = GlobalProtocol::builder("bad")
            .participant("alice", "role")
            .participant("bob", "role")
            .interaction(
                Interaction::comm("alice", "msg", "Msg", "bob")
                    .then(Interaction::continue_("nonexistent"))
                    .expect("comm interactions accept continuations"),
            )
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(
            |e| matches!(e, ValidationError::UndefinedLoopLabel { label } if label == "nonexistent")
        ));
    }

    #[test]
    fn detects_parallel_participant_overlap() {
        let protocol = example_scatter_gather_overlap();
        let errors = protocol.validate();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::ParallelParticipantOverlap { participant } if participant == "coordinator")));
    }

    #[test]
    fn detects_empty_protocol() {
        let protocol = GlobalProtocol::builder("empty")
            .participant("alice", "role")
            .interaction(Interaction::end())
            .build();

        let errors = protocol.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::EmptyProtocol))
        );
        assert!(!protocol.is_deadlock_free());
    }

    #[test]
    fn detects_no_participants() {
        let protocol = GlobalProtocol::builder("no_parts")
            .interaction(Interaction::end())
            .build();

        let errors = protocol.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::NoParticipants))
        );
        assert!(!protocol.is_deadlock_free());
    }

    // ------------------------------------------------------------------
    // Statistics
    // ------------------------------------------------------------------

    #[test]
    fn two_phase_commit_stats() {
        let protocol = example_two_phase_commit();
        let stats = protocol.stats();
        assert_eq!(stats.comm_count, 3); // reserve, commit, abort
        assert_eq!(stats.choice_count, 1);
        assert_eq!(stats.loop_count, 0);
        assert_eq!(stats.participant_count, 2);
        assert_eq!(stats.monotone_comm_count, 1); // reserve
        assert_eq!(stats.non_monotone_comm_count, 2); // commit, abort
    }

    #[test]
    fn lease_renewal_stats() {
        let protocol = example_lease_renewal();
        let stats = protocol.stats();
        assert_eq!(stats.comm_count, 3); // acquire, renew, release
        assert_eq!(stats.choice_count, 1);
        assert_eq!(stats.loop_count, 1);
        assert_eq!(stats.participant_count, 2);
    }

    #[test]
    fn saga_compensation_stats() {
        let protocol = example_saga_compensation();
        let stats = protocol.stats();
        assert_eq!(stats.compensate_count, 1);
        assert_eq!(stats.choice_count, 1);
        assert_eq!(stats.participant_count, 3);
    }

    // ------------------------------------------------------------------
    // Projection
    // ------------------------------------------------------------------

    #[test]
    fn project_two_phase_commit_coordinator() {
        let protocol = example_two_phase_commit();
        let local = protocol.project("coordinator").expect("projection failed");

        // Coordinator should: send reserve, then internal choice (commit or abort)
        match &local {
            LocalType::Send {
                action, to, then, ..
            } => {
                assert_eq!(action, "reserve");
                assert_eq!(to, "worker");
                match then.as_ref() {
                    LocalType::InternalChoice { predicate, .. } => {
                        assert_eq!(predicate, "commit_ready");
                    }
                    other => panic!("Expected InternalChoice, got {other}"),
                }
            }
            other => panic!("Expected Send, got {other}"),
        }
    }

    #[test]
    fn project_two_phase_commit_worker() {
        let protocol = example_two_phase_commit();
        let local = protocol.project("worker").expect("projection failed");

        // Worker should: recv reserve, then external choice
        match &local {
            LocalType::Recv {
                action, from, then, ..
            } => {
                assert_eq!(action, "reserve");
                assert_eq!(from, "coordinator");
                match then.as_ref() {
                    LocalType::ExternalChoice { from, .. } => {
                        assert_eq!(from, "coordinator");
                    }
                    other => panic!("Expected ExternalChoice, got {other}"),
                }
            }
            other => panic!("Expected Recv, got {other}"),
        }
    }

    #[test]
    fn project_lease_renewal_holder() {
        let protocol = example_lease_renewal();
        let local = protocol.project("holder").expect("projection failed");

        // Holder: send acquire, then recursive loop with internal choice
        match &local {
            LocalType::Send { action, then, .. } => {
                assert_eq!(action, "acquire");
                match then.as_ref() {
                    LocalType::Rec { label, .. } => {
                        assert_eq!(label, "renew_loop");
                    }
                    other => panic!("Expected Rec, got {other}"),
                }
            }
            other => panic!("Expected Send, got {other}"),
        }
    }

    #[test]
    fn project_returns_none_for_uninvolved_participant() {
        let protocol = example_two_phase_commit();
        assert!(protocol.project("uninvolved").is_none());
    }

    // ------------------------------------------------------------------
    // Display
    // ------------------------------------------------------------------

    #[test]
    fn display_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let output = format!("{}", protocol.interaction);
        assert!(output.contains("coordinator.reserve(ReserveMsg) -> worker"));
        assert!(output.contains("coordinator.decides(commit_ready)"));
        assert!(output.contains("[monotone]"));
    }

    #[test]
    fn display_local_type() {
        let protocol = example_two_phase_commit();
        let local = protocol.project("coordinator").unwrap();
        let output = format!("{local}");
        assert!(output.contains("!reserve(ReserveMsg) -> worker"));
        assert!(output.contains("decides(commit_ready)"));
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    #[test]
    fn nested_choice_validates() {
        let protocol = GlobalProtocol::builder("nested_choice")
            .participant("a", "role-a")
            .participant("b", "role-b")
            .interaction(Interaction::choice(
                "a",
                "outer",
                Interaction::comm("a", "m1", "M1", "b")
                    .then(Interaction::choice(
                        "a",
                        "inner",
                        Interaction::comm("a", "m2", "M2", "b")
                            .then(Interaction::end())
                            .expect("comm interactions accept continuations"),
                        Interaction::comm("a", "m3", "M3", "b")
                            .then(Interaction::end())
                            .expect("comm interactions accept continuations"),
                    ))
                    .expect("comm interactions accept continuations"),
                Interaction::comm("a", "m4", "M4", "b")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
            ))
            .build();

        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn generic_message_type() {
        let protocol = GlobalProtocol::builder("generic")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(
                Interaction::comm_generic("a", "send", "Payload", &["T"], "b")
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
            )
            .build();

        let errors = protocol.validate();
        assert!(errors.is_empty());

        let stats = protocol.stats();
        assert_eq!(stats.comm_count, 1);

        let output = format!("{}", protocol.interaction);
        assert!(output.contains("Payload<T>"));
    }

    #[test]
    fn compensation_projection() {
        let protocol = example_saga_compensation();
        let local_coord = protocol.project("coordinator").expect("projection failed");

        match &local_coord {
            LocalType::Compensate {
                forward,
                compensate,
            } => {
                // Forward should start with a send
                match forward.as_ref() {
                    LocalType::Send { action, .. } => assert_eq!(action, "reserve_a"),
                    other => panic!("Expected Send in forward, got {other}"),
                }
                // Compensate should start with a send
                match compensate.as_ref() {
                    LocalType::Send { action, .. } => assert_eq!(action, "compensate_a"),
                    other => panic!("Expected Send in compensate, got {other}"),
                }
            }
            other => panic!("Expected Compensate, got {other}"),
        }
    }

    #[test]
    fn compensation_only_participant_projection_preserves_scope() {
        let protocol = GlobalProtocol::builder("compensate_scope")
            .participant("a", "coordinator")
            .participant("b", "worker")
            .participant("c", "compensator")
            .interaction(Interaction::seq(
                Interaction::compensate(
                    Interaction::comm("a", "reserve", "Reserve", "b"),
                    Interaction::comm("a", "rollback", "Rollback", "c"),
                ),
                Interaction::comm("a", "notify", "Notify", "c"),
            ))
            .build();

        let local_c = protocol
            .project("c")
            .expect("projection for c should exist");
        match local_c {
            LocalType::Compensate {
                forward,
                compensate,
            } => {
                match forward.as_ref() {
                    LocalType::Recv {
                        action, from, then, ..
                    } => {
                        assert_eq!(action, "notify");
                        assert_eq!(from, "a");
                        assert!(matches!(then.as_ref(), LocalType::End));
                    }
                    other => panic!("expected notify in forward branch, got {other}"),
                }
                match compensate.as_ref() {
                    LocalType::Recv {
                        action, from, then, ..
                    } => {
                        assert_eq!(action, "rollback");
                        assert_eq!(from, "a");
                        assert!(matches!(then.as_ref(), LocalType::End));
                    }
                    other => panic!("expected rollback in compensate branch, got {other}"),
                }
            }
            other => panic!("expected compensate projection, got {other}"),
        }
    }

    #[test]
    fn duplicate_loop_label_detected() {
        let protocol = GlobalProtocol::builder("dup_labels")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::loop_(
                "x",
                Interaction::comm("a", "m", "M", "b")
                    .then(Interaction::loop_(
                        "x", // duplicate!
                        Interaction::comm("a", "n", "N", "b")
                            .then(Interaction::continue_("x"))
                            .expect("comm interactions accept continuations"),
                    ))
                    .expect("comm interactions accept continuations"),
            ))
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::DuplicateLoopLabel { label } if label == "x"
        )));
    }

    // ------------------------------------------------------------------
    // Livelock detection tests
    // ------------------------------------------------------------------

    #[test]
    fn immediate_livelock_detected() {
        // Loop body is just "continue self" - immediate infinite recursion
        let protocol = GlobalProtocol::builder("immediate_livelock")
            .participant("a", "role")
            .interaction(Interaction::loop_("loop1", Interaction::continue_("loop1")))
            .build();

        let errors = protocol.validate();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ValidationError::Livelock { label, reason }
                if label == "loop1" && reason.contains("immediate infinite recursion")
            )),
            "Expected immediate livelock error, got: {errors:?}"
        );
    }

    #[test]
    fn progress_free_loop_detected() {
        // Loop body has no communication but leads to continue
        let protocol = GlobalProtocol::builder("progress_free_loop")
            .participant("a", "role")
            .interaction(Interaction::loop_(
                "loop1",
                Interaction::choice(
                    "a",
                    "condition",
                    Interaction::continue_("loop1"), // no progress branch
                    Interaction::end(),
                ),
            ))
            .build();

        let errors = protocol.validate();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ValidationError::Livelock { label, reason }
                if label == "loop1" && reason.contains("no communication actions")
            )),
            "Expected progress-free livelock error, got: {errors:?}"
        );
    }

    #[test]
    fn loop_with_progress_is_valid() {
        // Loop body has communication before continue - this should be valid
        let protocol = GlobalProtocol::builder("loop_with_progress")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::loop_(
                "loop1",
                Interaction::comm("a", "msg", "M", "b")
                    .then(Interaction::choice(
                        "a",
                        "condition",
                        Interaction::continue_("loop1"),
                        Interaction::end(),
                    ))
                    .expect("comm interactions accept continuations"),
            ))
            .build();

        let errors = protocol.validate();
        let livelock_errors: Vec<_> = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::Livelock { .. }))
            .collect();
        assert!(
            livelock_errors.is_empty(),
            "Loop with communication should not trigger livelock: {livelock_errors:?}"
        );
    }

    #[test]
    fn nested_loop_livelock_detected() {
        // Nested loop where inner loop has immediate livelock
        let protocol = GlobalProtocol::builder("nested_loop_livelock")
            .participant("a", "role")
            .interaction(Interaction::loop_(
                "outer",
                Interaction::loop_(
                    "inner",
                    Interaction::continue_("inner"), // immediate livelock in inner loop
                ),
            ))
            .build();

        let errors = protocol.validate();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ValidationError::Livelock { label, .. } if label == "inner"
            )),
            "Expected livelock in inner loop, got: {errors:?}"
        );
    }

    #[test]
    fn sequence_with_progress_then_continue_is_valid() {
        // Sequence where we have progress before the continue
        let protocol = GlobalProtocol::builder("seq_with_progress")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::loop_(
                "loop1",
                Interaction::seq(
                    Interaction::comm("a", "work", "Work", "b"),
                    Interaction::continue_("loop1"),
                ),
            ))
            .build();

        let errors = protocol.validate();
        let livelock_errors: Vec<_> = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::Livelock { .. }))
            .collect();
        assert!(
            livelock_errors.is_empty(),
            "Sequential progress before continue should be valid: {livelock_errors:?}"
        );
    }

    #[test]
    fn choice_with_mixed_progress_detected() {
        // Choice where one branch has progress but the other doesn't
        let protocol = GlobalProtocol::builder("mixed_progress_choice")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::loop_(
                "loop1",
                Interaction::choice(
                    "a",
                    "condition",
                    // This branch has progress
                    Interaction::comm("a", "work", "Work", "b")
                        .then(Interaction::continue_("loop1"))
                        .expect("comm interactions accept continuations"),
                    // This branch has no progress - direct continue
                    Interaction::continue_("loop1"),
                ),
            ))
            .build();

        let errors = protocol.validate();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ValidationError::Livelock { label, reason }
                if label == "loop1" && reason.contains("no guaranteed progress")
            )),
            "Expected mixed progress livelock error, got: {errors:?}"
        );
    }

    // ==================================================================
    // bd-1f8jn.4: Comprehensive choreography test suite
    // ==================================================================

    // ------------------------------------------------------------------
    // Projection completeness: every message a participant sends/receives
    // in the global protocol must appear in their projected local type.
    // ------------------------------------------------------------------

    fn collect_local_actions(local: &LocalType) -> Vec<(String, &'static str)> {
        let mut actions = Vec::new();
        collect_local_actions_rec(local, &mut actions);
        actions
    }

    fn collect_local_actions_rec(local: &LocalType, out: &mut Vec<(String, &'static str)>) {
        match local {
            LocalType::Send { action, then, .. } => {
                out.push((action.clone(), "send"));
                collect_local_actions_rec(then, out);
            }
            LocalType::Recv { action, then, .. } => {
                out.push((action.clone(), "recv"));
                collect_local_actions_rec(then, out);
            }
            LocalType::InternalChoice {
                then_branch,
                else_branch,
                ..
            }
            | LocalType::ExternalChoice {
                then_branch,
                else_branch,
                ..
            } => {
                collect_local_actions_rec(then_branch, out);
                collect_local_actions_rec(else_branch, out);
            }
            LocalType::Rec { body, .. } => {
                collect_local_actions_rec(body, out);
            }
            LocalType::Compensate {
                forward,
                compensate,
            } => {
                collect_local_actions_rec(forward, out);
                collect_local_actions_rec(compensate, out);
            }
            LocalType::RecVar { .. } | LocalType::End => {}
        }
    }

    fn collect_global_actions(
        interaction: &Interaction,
        participant: &str,
    ) -> Vec<(String, &'static str)> {
        let mut actions = Vec::new();
        collect_global_actions_rec(interaction, participant, &mut actions);
        actions
    }

    fn collect_global_actions_rec(
        interaction: &Interaction,
        participant: &str,
        out: &mut Vec<(String, &'static str)>,
    ) {
        match interaction {
            Interaction::Comm {
                sender,
                receiver,
                action,
                then,
                ..
            } => {
                if sender == participant {
                    out.push((action.clone(), "send"));
                } else if receiver == participant {
                    out.push((action.clone(), "recv"));
                }
                collect_global_actions_rec(then, participant, out);
            }
            Interaction::Choice {
                then_branch,
                else_branch,
                ..
            } => {
                collect_global_actions_rec(then_branch, participant, out);
                collect_global_actions_rec(else_branch, participant, out);
            }
            Interaction::Loop { body, .. } => {
                collect_global_actions_rec(body, participant, out);
            }
            Interaction::Compensate {
                forward,
                compensate,
            } => {
                collect_global_actions_rec(forward, participant, out);
                collect_global_actions_rec(compensate, participant, out);
            }
            Interaction::Seq { first, second } => {
                collect_global_actions_rec(first, participant, out);
                collect_global_actions_rec(second, participant, out);
            }
            Interaction::Par { left, right } => {
                collect_global_actions_rec(left, participant, out);
                collect_global_actions_rec(right, participant, out);
            }
            Interaction::Continue { .. } | Interaction::End => {}
        }
    }

    #[test]
    fn projection_completeness_two_phase_commit() {
        let protocol = example_two_phase_commit();
        for name in protocol.participants.keys() {
            let global_actions = collect_global_actions(&protocol.interaction, name);
            if global_actions.is_empty() {
                assert!(protocol.project(name).is_none());
                continue;
            }
            let local = protocol.project(name).expect("projection should exist");
            let local_actions = collect_local_actions(&local);
            for (action, dir) in &global_actions {
                assert!(
                    local_actions.iter().any(|(a, d)| a == action && d == dir),
                    "Missing {action} ({dir}) in projection for {name}"
                );
            }
        }
    }

    #[test]
    fn projection_completeness_lease_renewal() {
        let protocol = example_lease_renewal();
        for name in protocol.participants.keys() {
            let global_actions = collect_global_actions(&protocol.interaction, name);
            if global_actions.is_empty() {
                continue;
            }
            let local = protocol.project(name).expect("projection should exist");
            let local_actions = collect_local_actions(&local);
            for (action, dir) in &global_actions {
                assert!(
                    local_actions.iter().any(|(a, d)| a == action && d == dir),
                    "Missing {action} ({dir}) in projection for {name}"
                );
            }
        }
    }

    #[test]
    fn projection_completeness_saga_compensation() {
        let protocol = example_saga_compensation();
        for name in protocol.participants.keys() {
            let global_actions = collect_global_actions(&protocol.interaction, name);
            if global_actions.is_empty() {
                continue;
            }
            let local = protocol.project(name).expect("projection should exist");
            let local_actions = collect_local_actions(&local);
            for (action, dir) in &global_actions {
                assert!(
                    local_actions.iter().any(|(a, d)| a == action && d == dir),
                    "Missing {action} ({dir}) in projection for {name}"
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Projection duality: for each Comm(sender→receiver), the sender's
    // projection has a Send and the receiver's has a Recv.
    // ------------------------------------------------------------------

    #[test]
    fn projection_duality_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let coord = protocol
            .project("coordinator")
            .expect("coordinator projection");
        let worker = protocol.project("worker").expect("worker projection");

        let coord_actions = collect_local_actions(&coord);
        let worker_actions = collect_local_actions(&worker);

        assert!(coord_actions.contains(&("reserve".to_string(), "send")));
        assert!(worker_actions.contains(&("reserve".to_string(), "recv")));
        assert!(coord_actions.contains(&("commit".to_string(), "send")));
        assert!(worker_actions.contains(&("commit".to_string(), "recv")));
        assert!(coord_actions.contains(&("abort".to_string(), "send")));
        assert!(worker_actions.contains(&("abort".to_string(), "recv")));
    }

    #[test]
    fn projection_duality_lease_renewal() {
        let protocol = example_lease_renewal();
        let holder = protocol.project("holder").expect("holder projection");
        let resource = protocol.project("resource").expect("resource projection");

        let holder_actions = collect_local_actions(&holder);
        let resource_actions = collect_local_actions(&resource);

        for (action, dir) in &holder_actions {
            let expected_dir = if *dir == "send" { "recv" } else { "send" };
            assert!(
                resource_actions
                    .iter()
                    .any(|(a, d)| a == action && *d == expected_dir),
                "Duality violation: holder {dir}s {action}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Knowledge-of-choice: comprehensive edge cases
    // ------------------------------------------------------------------

    #[test]
    fn knowledge_of_choice_nested_choice_both_valid() {
        let protocol = GlobalProtocol::builder("nested_valid")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::choice(
                "a",
                "outer",
                Interaction::comm("a", "m1", "M1", "b")
                    .then(Interaction::choice(
                        "a",
                        "inner",
                        Interaction::comm("a", "m2", "M2", "b"),
                        Interaction::comm("a", "m3", "M3", "b"),
                    ))
                    .expect("comm interactions accept continuations"),
                Interaction::comm("a", "m4", "M4", "b"),
            ))
            .build();
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn knowledge_of_choice_nested_different_deciders_valid() {
        let protocol = GlobalProtocol::builder("nested_diff")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::choice(
                "a",
                "outer",
                Interaction::comm("a", "notify", "Notify", "b")
                    .then(Interaction::choice(
                        "b",
                        "inner",
                        Interaction::comm("b", "reply_yes", "Yes", "a"),
                        Interaction::comm("b", "reply_no", "No", "a"),
                    ))
                    .expect("comm interactions accept continuations"),
                Interaction::comm("a", "skip", "Skip", "b"),
            ))
            .build();
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn knowledge_of_choice_violation_in_else_branch() {
        let protocol = GlobalProtocol::builder("bad_else")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::choice(
                "a",
                "pred",
                Interaction::comm("a", "ok", "Ok", "b"),
                Interaction::comm("b", "nope", "Nope", "a"),
            ))
            .build();
        let errors = protocol.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::KnowledgeOfChoice { branch: "else", .. }))
        );
        assert!(!protocol.is_deadlock_free());
    }

    #[test]
    fn knowledge_of_choice_violation_both_branches() {
        let protocol = GlobalProtocol::builder("bad_both")
            .participant("a", "role")
            .participant("b", "role")
            .participant("c", "role")
            .interaction(Interaction::choice(
                "c",
                "pred",
                Interaction::comm("a", "m1", "M1", "b"),
                Interaction::comm("b", "m2", "M2", "a"),
            ))
            .build();
        let errors = protocol.validate();
        assert_eq!(
            errors
                .iter()
                .filter(|e| matches!(e, ValidationError::KnowledgeOfChoice { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn knowledge_of_choice_within_loop() {
        let protocol = GlobalProtocol::builder("choice_in_loop")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::loop_(
                "main",
                Interaction::choice(
                    "a",
                    "continue_pred",
                    Interaction::comm("a", "data", "Data", "b")
                        .then(Interaction::continue_("main"))
                        .expect("comm interactions accept continuations"),
                    Interaction::comm("a", "done", "Done", "b"),
                ),
            ))
            .build();
        assert!(protocol.validate().is_empty());
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn knowledge_of_choice_within_compensation() {
        let protocol = GlobalProtocol::builder("choice_in_comp")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::compensate(
                Interaction::choice(
                    "a",
                    "which_path",
                    Interaction::comm("a", "path1", "P1", "b"),
                    Interaction::comm("a", "path2", "P2", "b"),
                ),
                Interaction::comm("a", "rollback", "Rollback", "b"),
            ))
            .build();
        assert!(protocol.validate().is_empty());
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn knowledge_of_choice_violation_detected_when_seq_prefix_is_inert() {
        let protocol = GlobalProtocol::builder("choice_seq_inert_prefix")
            .participant("a", "role")
            .participant("b", "role")
            .participant("c", "role")
            .interaction(Interaction::choice(
                "a",
                "pred",
                Interaction::seq(
                    Interaction::end(),
                    Interaction::comm("b", "late_then_send", "Msg", "c"),
                ),
                Interaction::comm("a", "ok_else_send", "Msg", "b"),
            ))
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(|e| {
            matches!(
                e,
                ValidationError::KnowledgeOfChoice {
                    branch: "then",
                    first_sender: Some(first_sender),
                    ..
                } if first_sender == "b"
            )
        }));
    }

    #[test]
    fn knowledge_of_choice_violation_detected_when_par_left_is_inert() {
        let protocol = GlobalProtocol::builder("choice_par_inert_left")
            .participant("a", "role")
            .participant("b", "role")
            .participant("c", "role")
            .interaction(Interaction::choice(
                "a",
                "pred",
                Interaction::par(
                    Interaction::end(),
                    Interaction::comm("b", "late_parallel_send", "Msg", "c"),
                ),
                Interaction::comm("a", "ok_else_send", "Msg", "b"),
            ))
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(|e| {
            matches!(
                e,
                ValidationError::KnowledgeOfChoice {
                    branch: "then",
                    first_sender: Some(first_sender),
                    ..
                } if first_sender == "b"
            )
        }));
    }

    #[test]
    fn knowledge_of_choice_violation_detected_when_parallel_branch_starts_elsewhere() {
        // Then branch starts with parallel sends from both `a` (decider) and `c`.
        // Even though `a` can send first in one branch, `c` can also send first
        // in the other branch, violating knowledge-of-choice for that branch.
        let protocol = GlobalProtocol::builder("choice_parallel_mixed_starters")
            .participant("a", "role")
            .participant("b", "role")
            .participant("c", "role")
            .participant("d", "role")
            .interaction(Interaction::choice(
                "a",
                "pred",
                Interaction::par(
                    Interaction::comm("a", "left_start", "Msg", "b"),
                    Interaction::comm("c", "right_start", "Msg", "d"),
                ),
                Interaction::comm("a", "else_start", "Msg", "b"),
            ))
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(|e| {
            matches!(
                e,
                ValidationError::KnowledgeOfChoice {
                    branch: "then",
                    first_sender: Some(first_sender),
                    ..
                } if first_sender == "c"
            )
        }));
    }

    // ------------------------------------------------------------------
    // Complex protocol tests
    // ------------------------------------------------------------------

    #[test]
    fn four_participant_saga_validates() {
        let protocol = GlobalProtocol::builder("four_party_saga")
            .participant("coord", "coordinator")
            .participant("auth", "auth-service")
            .participant("payment", "payment-service")
            .participant("inventory", "inventory-service")
            .interaction(Interaction::seq(
                Interaction::comm("coord", "check_auth", "AuthReq", "auth"),
                Interaction::seq(
                    Interaction::comm("auth", "auth_result", "AuthResp", "coord"),
                    Interaction::choice(
                        "coord",
                        "auth_ok",
                        Interaction::seq(
                            Interaction::comm("coord", "charge", "PayReq", "payment"),
                            Interaction::seq(
                                Interaction::comm("payment", "pay_result", "PayResp", "coord"),
                                Interaction::seq(
                                    Interaction::comm(
                                        "coord",
                                        "reserve_stock",
                                        "InvReq",
                                        "inventory",
                                    ),
                                    Interaction::comm(
                                        "inventory",
                                        "stock_result",
                                        "InvResp",
                                        "coord",
                                    ),
                                ),
                            ),
                        ),
                        Interaction::comm("coord", "reject", "RejectMsg", "auth"),
                    ),
                ),
            ))
            .build();

        assert!(protocol.validate().is_empty());
        assert!(protocol.is_deadlock_free());

        for name in protocol.participants.keys() {
            let global = collect_global_actions(&protocol.interaction, name);
            if global.is_empty() {
                continue;
            }
            let local = protocol.project(name).expect("projection exists");
            let local_acts = collect_local_actions(&local);
            for (action, dir) in &global {
                assert!(
                    local_acts.iter().any(|(a, d)| a == action && d == dir),
                    "{name}: missing {action} ({dir})"
                );
            }
        }
    }

    #[test]
    fn deeply_nested_protocol_validates() {
        let protocol = GlobalProtocol::builder("deep")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::loop_(
                "outer",
                Interaction::choice(
                    "a",
                    "should_continue",
                    Interaction::seq(
                        Interaction::compensate(
                            Interaction::seq(
                                Interaction::comm("a", "step1", "S1", "b"),
                                Interaction::comm("a", "step2", "S2", "b"),
                            ),
                            Interaction::comm("a", "undo", "Undo", "b"),
                        ),
                        Interaction::continue_("outer"),
                    ),
                    Interaction::comm("a", "finish", "Finish", "b"),
                ),
            ))
            .build();

        assert!(protocol.validate().is_empty());
        let stats = protocol.stats();
        assert!(stats.max_depth >= 3);
        assert_eq!(stats.loop_count, 1);
        assert_eq!(stats.choice_count, 1);
        assert_eq!(stats.compensate_count, 1);
    }

    // ------------------------------------------------------------------
    // Stats consistency
    // ------------------------------------------------------------------

    #[test]
    fn stats_comm_count_matches_tree() {
        let protocol = example_saga_compensation();
        let stats = protocol.stats();
        assert_eq!(stats.comm_count, 8);
    }

    #[test]
    fn stats_participant_count_matches_references() {
        let protocol = example_two_phase_commit();
        let stats = protocol.stats();
        let referenced = protocol.interaction.referenced_participants();
        assert_eq!(stats.participant_count, referenced.len());
    }

    #[test]
    fn stats_par_count() {
        let protocol = example_scatter_gather_disjoint();
        let stats = protocol.stats();
        assert_eq!(stats.par_count, 1);
        assert_eq!(stats.comm_count, 4);
    }

    // ------------------------------------------------------------------
    // Display determinism
    // ------------------------------------------------------------------

    #[test]
    fn display_deterministic() {
        let p1 = example_two_phase_commit();
        let p2 = example_two_phase_commit();
        assert_eq!(format!("{}", p1.interaction), format!("{}", p2.interaction));
    }

    #[test]
    fn local_type_display_deterministic() {
        let protocol = example_two_phase_commit();
        let l1 = protocol.project("coordinator").unwrap();
        let l2 = protocol.project("coordinator").unwrap();
        assert_eq!(format!("{l1}"), format!("{l2}"));
    }

    // ------------------------------------------------------------------
    // Validation error Display coverage
    // ------------------------------------------------------------------

    #[test]
    fn validation_error_display_coverage() {
        let errors = vec![
            ValidationError::UndeclaredParticipant {
                name: "x".into(),
                context: "test".into(),
            },
            ValidationError::SelfCommunication {
                participant: "a".into(),
                action: "ping".into(),
            },
            ValidationError::KnowledgeOfChoice {
                decider: "a".into(),
                branch: "then",
                first_sender: Some("b".into()),
            },
            ValidationError::KnowledgeOfChoice {
                decider: "a".into(),
                branch: "else",
                first_sender: None,
            },
            ValidationError::UndefinedLoopLabel { label: "x".into() },
            ValidationError::DuplicateLoopLabel { label: "x".into() },
            ValidationError::EmptyProtocol,
            ValidationError::ParallelParticipantOverlap {
                participant: "a".into(),
            },
            ValidationError::DuplicateParticipant { name: "a".into() },
            ValidationError::NoParticipants,
        ];
        for e in &errors {
            let msg = format!("{e}");
            assert!(!msg.is_empty(), "Empty Display for {e:?}");
        }
    }

    // ------------------------------------------------------------------
    // Projection edge cases
    // ------------------------------------------------------------------

    #[test]
    fn project_participant_only_in_one_par_branch() {
        let protocol = example_scatter_gather_disjoint();
        let local_a = protocol.project("worker_a").expect("should project");
        let actions = collect_local_actions(&local_a);
        assert!(
            actions
                .iter()
                .any(|(a, d)| a == "request_a" && *d == "recv")
        );
        assert!(
            actions
                .iter()
                .any(|(a, d)| a == "response_a" && *d == "send")
        );
        assert!(!actions.iter().any(|(a, _)| a == "request_b"));
    }

    #[test]
    fn project_seq_local_threads_continuations() {
        let protocol = GlobalProtocol::builder("seq_test")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::seq(
                Interaction::comm("a", "m1", "M1", "b"),
                Interaction::comm("a", "m2", "M2", "b"),
            ))
            .build();

        let local_a = protocol.project("a").expect("projection exists");
        match &local_a {
            LocalType::Send {
                action, then: t1, ..
            } => {
                assert_eq!(action, "m1");
                match t1.as_ref() {
                    LocalType::Send {
                        action, then: t2, ..
                    } => {
                        assert_eq!(action, "m2");
                        assert!(matches!(t2.as_ref(), LocalType::End));
                    }
                    other => panic!("Expected Send m2, got {other}"),
                }
            }
            other => panic!("Expected Send m1, got {other}"),
        }
    }

    #[test]
    fn project_choice_uninvolved_participant_gets_branch() {
        let protocol = GlobalProtocol::builder("choice_uninvolved")
            .participant("a", "role")
            .participant("b", "role")
            .participant("c", "role")
            .interaction(Interaction::seq(
                Interaction::choice(
                    "a",
                    "pred",
                    Interaction::comm("a", "yes", "Yes", "b"),
                    Interaction::comm("a", "no", "No", "b"),
                ),
                Interaction::comm("a", "notify", "Notify", "c"),
            ))
            .build();

        let local_c = protocol.project("c").expect("c should project");
        match &local_c {
            LocalType::Recv { action, .. } => assert_eq!(action, "notify"),
            other => panic!("Expected Recv notify, got {other}"),
        }
    }

    #[test]
    fn project_choice_single_branch_participant_keeps_choice_structure() {
        let protocol = GlobalProtocol::builder("choice_single_branch")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::choice(
                "a",
                "pred",
                Interaction::comm("a", "maybe_send", "Msg", "b"),
                Interaction::end(),
            ))
            .build();

        assert!(protocol.validate().is_empty());

        let local_a = protocol.project("a").expect("a should project");
        match &local_a {
            LocalType::InternalChoice {
                predicate,
                then_branch,
                else_branch,
            } => {
                assert_eq!(predicate, "pred");
                assert!(matches!(else_branch.as_ref(), LocalType::End));
                match then_branch.as_ref() {
                    LocalType::Send { action, .. } => assert_eq!(action, "maybe_send"),
                    other => panic!("Expected Send in then branch, got {other}"),
                }
            }
            other => panic!("Expected InternalChoice, got {other}"),
        }

        let local_b = protocol.project("b").expect("b should project");
        match &local_b {
            LocalType::ExternalChoice {
                from,
                then_branch,
                else_branch,
            } => {
                assert_eq!(from, "a");
                assert!(matches!(else_branch.as_ref(), LocalType::End));
                match then_branch.as_ref() {
                    LocalType::Recv { action, .. } => assert_eq!(action, "maybe_send"),
                    other => panic!("Expected Recv in then branch, got {other}"),
                }
            }
            other => panic!("Expected ExternalChoice, got {other}"),
        }
    }

    #[test]
    fn seq_after_choice_threads_into_both_projected_branches() {
        let protocol = GlobalProtocol::builder("choice_then_seq")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::seq(
                Interaction::choice(
                    "a",
                    "pred",
                    Interaction::comm("a", "maybe_send", "Msg", "b"),
                    Interaction::end(),
                ),
                Interaction::comm("a", "always_send", "Msg2", "b"),
            ))
            .build();

        assert!(protocol.validate().is_empty());

        let local_b = protocol.project("b").expect("b should project");
        match &local_b {
            LocalType::ExternalChoice {
                then_branch,
                else_branch,
                ..
            } => {
                match then_branch.as_ref() {
                    LocalType::Recv { action, then, .. } => {
                        assert_eq!(action, "maybe_send");
                        match then.as_ref() {
                            LocalType::Recv { action, .. } => assert_eq!(action, "always_send"),
                            other => panic!("Expected Recv(always_send), got {other}"),
                        }
                    }
                    other => panic!("Expected Recv(maybe_send) in then branch, got {other}"),
                }
                match else_branch.as_ref() {
                    LocalType::Recv { action, .. } => assert_eq!(action, "always_send"),
                    other => panic!("Expected Recv(always_send) in else branch, got {other}"),
                }
            }
            other => panic!("Expected ExternalChoice, got {other}"),
        }
    }

    #[test]
    fn project_compensation_only_forward_for_uninvolved() {
        let protocol = GlobalProtocol::builder("comp_partial")
            .participant("a", "role")
            .participant("b", "role")
            .participant("c", "role")
            .interaction(Interaction::compensate(
                Interaction::comm("a", "fwd", "Fwd", "b"),
                Interaction::comm("a", "comp", "Comp", "c"),
            ))
            .build();

        let local_b = protocol.project("b").expect("b should project");
        let b_actions = collect_local_actions(&local_b);
        assert!(b_actions.iter().any(|(a, _)| a == "fwd"));
        assert!(!b_actions.iter().any(|(a, _)| a == "comp"));

        let local_c = protocol.project("c").expect("c should project");
        let c_actions = collect_local_actions(&local_c);
        assert!(c_actions.iter().any(|(a, _)| a == "comp"));
        assert!(!c_actions.iter().any(|(a, _)| a == "fwd"));
    }

    fn has_rec_var(local: &LocalType, label: &str) -> bool {
        match local {
            LocalType::RecVar { label: l } => l == label,
            LocalType::Send { then, .. } | LocalType::Recv { then, .. } => has_rec_var(then, label),
            LocalType::InternalChoice {
                then_branch,
                else_branch,
                ..
            }
            | LocalType::ExternalChoice {
                then_branch,
                else_branch,
                ..
            } => has_rec_var(then_branch, label) || has_rec_var(else_branch, label),
            LocalType::Rec { body, .. } => has_rec_var(body, label),
            LocalType::Compensate {
                forward,
                compensate,
            } => has_rec_var(forward, label) || has_rec_var(compensate, label),
            LocalType::End => false,
        }
    }

    #[test]
    fn project_loop_with_continue_produces_rec_var() {
        let protocol = example_lease_renewal();
        let local = protocol.project("holder").expect("projection exists");
        assert!(has_rec_var(&local, "renew_loop"));
    }

    // ------------------------------------------------------------------
    // Builder API edge cases
    // ------------------------------------------------------------------

    #[test]
    fn comm_calm_monotone_appears_in_display() {
        let interaction =
            Interaction::comm_calm("a", "test", "TestMsg", "b", Monotonicity::Monotone);
        assert!(format!("{interaction}").contains("[monotone]"));
    }

    #[test]
    fn comm_calm_non_monotone_appears_in_display() {
        let interaction =
            Interaction::comm_calm("a", "test", "TestMsg", "b", Monotonicity::NonMonotone);
        assert!(format!("{interaction}").contains("[non-monotone]"));
    }

    #[test]
    fn message_type_display_with_type_params() {
        let mt = MessageType {
            name: "Payload".into(),
            type_params: vec!["T".into(), "U".into()],
        };
        assert_eq!(format!("{mt}"), "Payload<T, U>");
    }

    #[test]
    fn message_type_display_no_type_params() {
        let mt = MessageType {
            name: "Simple".into(),
            type_params: vec![],
        };
        assert_eq!(format!("{mt}"), "Simple");
    }

    #[test]
    fn then_rejects_non_comm_interactions() {
        let error = Interaction::end()
            .then(Interaction::end())
            .expect_err("non-comm interactions should reject direct continuations");
        assert_eq!(
            error,
            ChoreographyBuildError::InvalidContinuationTarget { kind: "end" }
        );
    }

    #[test]
    fn builder_without_interaction_validates_as_empty_protocol() {
        let protocol = GlobalProtocol::builder("bad")
            .participant("a", "role")
            .build();
        assert!(matches!(protocol.interaction, Interaction::End));
        assert!(
            protocol
                .validate()
                .iter()
                .any(|error| matches!(error, ValidationError::EmptyProtocol))
        );
    }

    // ------------------------------------------------------------------
    // first_active_participant coverage
    // ------------------------------------------------------------------

    #[test]
    fn first_active_in_seq_is_first_branch() {
        let inter = Interaction::seq(
            Interaction::comm("a", "m", "M", "b"),
            Interaction::comm("c", "n", "N", "b"),
        );
        assert_eq!(inter.first_active_participant(), Some("a"));
    }

    #[test]
    fn first_active_in_compensate_is_forward() {
        let inter = Interaction::compensate(
            Interaction::comm("a", "fwd", "F", "b"),
            Interaction::comm("c", "comp", "C", "b"),
        );
        assert_eq!(inter.first_active_participant(), Some("a"));
    }

    #[test]
    fn first_active_in_par_is_left() {
        let inter = Interaction::par(
            Interaction::comm("a", "left", "L", "b"),
            Interaction::comm("c", "right", "R", "d"),
        );
        assert_eq!(inter.first_active_participant(), Some("a"));
    }

    #[test]
    fn first_active_in_end_is_none() {
        assert!(Interaction::end().first_active_participant().is_none());
    }

    #[test]
    fn first_active_in_continue_is_none() {
        assert!(
            Interaction::continue_("x")
                .first_active_participant()
                .is_none()
        );
    }

    // ------------------------------------------------------------------
    // Multiple errors detected simultaneously
    // ------------------------------------------------------------------

    #[test]
    fn multiple_errors_detected_at_once() {
        let protocol = GlobalProtocol::builder("multi_bad")
            .participant("a", "role")
            .interaction(
                Interaction::comm("a", "ping", "Ping", "a")
                    .then(Interaction::comm("a", "send", "Msg", "ghost"))
                    .expect("comm interactions accept continuations"),
            )
            .build();

        let errors = protocol.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::SelfCommunication { .. }))
        );
        assert!(errors.iter().any(
            |e| matches!(e, ValidationError::UndeclaredParticipant { name, .. } if name == "ghost")
        ));
    }

    // ------------------------------------------------------------------
    // referenced_participants correctness
    // ------------------------------------------------------------------

    #[test]
    fn referenced_participants_collects_all() {
        let inter = Interaction::seq(
            Interaction::comm("a", "m1", "M", "b"),
            Interaction::par(
                Interaction::comm("c", "m2", "M", "d"),
                Interaction::compensate(
                    Interaction::comm("e", "m3", "M", "f"),
                    Interaction::comm("g", "m4", "M", "h"),
                ),
            ),
        );

        let refs = inter.referenced_participants();
        for name in &["a", "b", "c", "d", "e", "f", "g", "h"] {
            assert!(refs.contains(*name), "Missing participant {name}");
        }
        assert_eq!(refs.len(), 8);
    }

    // ------------------------------------------------------------------
    // Bug fix: loop label scoping (labels must not leak into siblings)
    // ------------------------------------------------------------------

    #[test]
    fn continue_to_sibling_loop_detected() {
        // Loop("x", ...) followed by Continue("x") in a Seq — the Continue
        // references a non-enclosing loop, which should be an error.
        let protocol = GlobalProtocol::builder("sibling_continue")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::seq(
                Interaction::loop_(
                    "x",
                    Interaction::comm("a", "m", "M", "b")
                        .then(Interaction::continue_("x"))
                        .expect("comm interactions accept continuations"),
                ),
                Interaction::continue_("x"), // "x" is NOT enclosing here
            ))
            .build();

        let errors = protocol.validate();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ValidationError::UndefinedLoopLabel { label } if label == "x"
            )),
            "Continue to sibling loop should be detected: {errors:?}"
        );
    }

    #[test]
    fn loop_label_does_not_leak_across_choice_branches() {
        // Loop("x") in then-branch should not be visible in else-branch.
        let protocol = GlobalProtocol::builder("choice_label_leak")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::choice(
                "a",
                "pred",
                Interaction::comm("a", "m1", "M", "b")
                    .then(Interaction::loop_(
                        "inner",
                        Interaction::comm("a", "ping", "Ping", "b")
                            .then(Interaction::continue_("inner"))
                            .expect("comm interactions accept continuations"),
                    ))
                    .expect("comm interactions accept continuations"),
                Interaction::comm("a", "m2", "M", "b")
                    .then(Interaction::continue_("inner"))
                    .expect("comm interactions accept continuations"), // NOT enclosing
            ))
            .build();

        let errors = protocol.validate();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ValidationError::UndefinedLoopLabel { label } if label == "inner"
            )),
            "Loop label should not leak across choice branches: {errors:?}"
        );
    }

    // ------------------------------------------------------------------
    // Bug fix: Continue projection for uninvolved participants
    // ------------------------------------------------------------------

    #[test]
    fn uninvolved_participant_not_trapped_in_loop() {
        // Participant "c" is not in the loop body but appears after the
        // loop in a Seq.  Before the fix, projection produced a vacuous
        // Rec { body: RecVar } that swallowed the subsequent Recv.
        let protocol = GlobalProtocol::builder("continue_projection")
            .participant("a", "role")
            .participant("b", "role")
            .participant("c", "role")
            .interaction(Interaction::seq(
                Interaction::loop_(
                    "x",
                    Interaction::comm("a", "ping", "Ping", "b")
                        .then(Interaction::continue_("x"))
                        .expect("comm interactions accept continuations"),
                ),
                Interaction::comm("a", "notify", "Notify", "c"),
            ))
            .build();

        assert!(protocol.validate().is_empty(), "should be valid");

        let local_c = protocol
            .project("c")
            .expect("c should project (has actions after loop)");
        let actions = collect_local_actions(&local_c);
        assert!(
            actions.iter().any(|(a, d)| a == "notify" && *d == "recv"),
            "c must receive 'notify' after uninvolved loop, got: {local_c}"
        );
    }

    #[test]
    fn involved_participant_still_gets_loop() {
        // Participant "b" IS involved in the loop body — they should still
        // get a proper Rec/RecVar projection.
        let protocol = GlobalProtocol::builder("involved_loop")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::loop_(
                "x",
                Interaction::choice(
                    "a",
                    "go",
                    Interaction::comm("a", "data", "Data", "b")
                        .then(Interaction::continue_("x"))
                        .expect("comm interactions accept continuations"),
                    Interaction::comm("a", "done", "Done", "b"),
                ),
            ))
            .build();

        assert!(protocol.validate().is_empty());

        let local_b = protocol
            .project("b")
            .expect("b should project (involved in loop)");
        assert!(
            has_rec_var(&local_b, "x"),
            "b should have RecVar for loop 'x', got: {local_b}"
        );
    }

    // ------------------------------------------------------------------
    // Proptest: randomly generated choreographies (bd-1f8jn.4 item 1)
    // ------------------------------------------------------------------
    //
    // Since there is no parser for the DSL (only a builder API), we test
    // structural invariants: validation catches errors, valid protocols
    // project successfully, projections are consistent.

    mod proptest_choreography {
        use super::*;
        use proptest::prelude::*;

        /// Pool of participant names for random generation.
        const NAMES: &[&str] = &["alice", "bob", "carol", "dave"];
        const ACTIONS: &[&str] = &["ping", "pong", "req", "resp", "ack", "data"];
        const MSG_TYPES: &[&str] = &["Ping", "Pong", "Request", "Response", "Ack", "Data"];

        /// Generate a random Interaction tree of bounded depth.
        fn arb_interaction(depth: u32) -> BoxedStrategy<Interaction> {
            if depth == 0 {
                // Leaf: comm between two distinct participants
                (
                    prop::sample::select(NAMES),
                    prop::sample::select(NAMES),
                    prop::sample::select(ACTIONS),
                    prop::sample::select(MSG_TYPES),
                )
                    .prop_filter("distinct participants", |(s, r, _, _)| s != r)
                    .prop_map(|(sender, receiver, action, msg)| {
                        Interaction::comm(sender, action, msg, receiver)
                    })
                    .boxed()
            } else {
                let leaf = arb_interaction(0);

                prop_oneof![
                    // Comm
                    4 => leaf,
                    // Seq
                    2 => (arb_interaction(depth - 1), arb_interaction(depth - 1))
                        .prop_map(|(a, b)| Interaction::seq(a, b)),
                    // Choice (decider + two branches)
                    1 => (
                        prop::sample::select(NAMES),
                        arb_interaction(depth - 1),
                        arb_interaction(depth - 1),
                    ).prop_map(|(decider, then_b, else_b)| {
                        Interaction::choice(decider, "cond", then_b, else_b)
                    }),
                    // Compensate
                    1 => (arb_interaction(depth - 1), arb_interaction(depth - 1))
                        .prop_map(|(fwd, comp)| Interaction::compensate(fwd, comp)),
                ]
                .boxed()
            }
        }

        /// Build a GlobalProtocol from a random interaction, adding all
        /// referenced participants.
        fn build_protocol(name: &str, interaction: Interaction) -> GlobalProtocol {
            let refs = interaction.referenced_participants();
            let mut builder = GlobalProtocol::builder(name);
            for p in &refs {
                builder = builder.participant(p, "test-role");
            }
            builder.interaction(interaction).build()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(200))]

            /// Validation never panics on randomly generated protocols.
            #[test]
            fn validation_never_panics(interaction in arb_interaction(3)) {
                let protocol = build_protocol("proptest_protocol", interaction);
                let _ = protocol.validate(); // must not panic
            }

            /// Referenced participants are always a subset of declared participants.
            #[test]
            fn referenced_subset_of_declared(interaction in arb_interaction(3)) {
                let protocol = build_protocol("proptest_protocol", interaction);
                let declared: std::collections::HashSet<&str> =
                    protocol.participants.keys().map(String::as_str).collect();
                let referenced = protocol.interaction.referenced_participants();
                for r in &referenced {
                    prop_assert!(
                        declared.contains(r.as_str()),
                        "referenced participant {} not in declared set",
                        r
                    );
                }
            }

            /// Valid protocols project to Some for every declared participant that
            /// is referenced in interactions.
            #[test]
            fn valid_protocols_project_all_participants(interaction in arb_interaction(2)) {
                let protocol = build_protocol("proptest_protocol", interaction);
                let errors = protocol.validate();
                if errors.is_empty() {
                    let referenced = protocol.interaction.referenced_participants();
                    for name in &referenced {
                        let local = protocol.project(name);
                        prop_assert!(
                            local.is_some(),
                            "valid protocol should project for referenced participant {}",
                            name
                        );
                    }
                }
            }

            /// Projection duality: if A sends to B, then B receives from A.
            #[test]
            fn projection_duality_for_comm(
                sender_idx in 0..NAMES.len(),
                receiver_idx in 0..NAMES.len(),
                action_idx in 0..ACTIONS.len(),
                msg_idx in 0..MSG_TYPES.len(),
            ) {
                let sender = NAMES[sender_idx];
                let receiver = NAMES[receiver_idx];
                prop_assume!(sender != receiver);

                let action = ACTIONS[action_idx];
                let msg = MSG_TYPES[msg_idx];

                let protocol = GlobalProtocol::builder("duality_test")
                    .participant(sender, "role")
                    .participant(receiver, "role")
                    .interaction(Interaction::comm(sender, action, msg, receiver))
                    .build();

                let errors = protocol.validate();
                prop_assert!(errors.is_empty(), "simple comm should validate");

                let sender_local = protocol.project(sender).expect("sender should project");
                let receiver_local = protocol.project(receiver).expect("receiver should project");

                // Sender projection should be Send
                prop_assert!(
                    matches!(sender_local, LocalType::Send { .. }),
                    "sender projection should be Send, got {:?}",
                    sender_local
                );

                // Receiver projection should be Recv
                prop_assert!(
                    matches!(receiver_local, LocalType::Recv { .. }),
                    "receiver projection should be Recv, got {:?}",
                    receiver_local
                );
            }

            /// Stats participant count matches referenced participants for valid protocols.
            #[test]
            fn stats_participant_count_consistent(interaction in arb_interaction(2)) {
                let protocol = build_protocol("proptest_protocol", interaction);
                let errors = protocol.validate();
                if errors.is_empty() {
                    let stats = protocol.stats();
                    let referenced = protocol.interaction.referenced_participants();
                    prop_assert_eq!(
                        stats.participant_count,
                        referenced.len(),
                        "stats participant count should match referenced count"
                    );
                }
            }
        }
    }
