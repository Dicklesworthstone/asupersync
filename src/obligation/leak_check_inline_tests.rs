    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn v(n: u32) -> ObligationVar {
        ObligationVar(n)
    }

    // ---- Clean paths -------------------------------------------------------

    #[test]
    fn clean_reserve_commit() {
        init_test("clean_reserve_commit");
        let body = Body::new(
            "clean_fn",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("clean_reserve_commit");
    }

    #[test]
    fn clean_reserve_abort() {
        init_test("clean_reserve_abort");
        let body = Body::new(
            "clean_abort",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Ack,
                },
                Instruction::Abort { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("clean_reserve_abort");
    }

    #[test]
    fn clean_branch_both_resolve() {
        init_test("clean_branch_both_resolve");
        let body = Body::new(
            "clean_branch",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("clean_branch_both_resolve");
    }

    #[test]
    fn clean_multiple_obligations() {
        init_test("clean_multiple_obligations");
        let body = Body::new(
            "multi_clean",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Commit { var: v(0) },
                Instruction::Commit { var: v(1) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("clean_multiple_obligations");
    }

    #[test]
    fn runtime_validator_detects_double_resolve_on_live_path() {
        init_test("runtime_validator_detects_double_resolve_on_live_path");
        let var = v(9);
        let mut validator = RuntimeObligationValidator::new("runtime_double_resolve");

        let diagnostics = validator.reserve(var, ObligationKind::SendPermit);
        crate::assert_with_log!(
            diagnostics.is_empty(),
            "reserve clean",
            true,
            diagnostics.len()
        );
        let diagnostics = validator.commit(var);
        crate::assert_with_log!(
            diagnostics.is_empty(),
            "commit clean",
            true,
            diagnostics.len()
        );
        let diagnostics = validator.abort(var);
        crate::assert_with_log!(
            diagnostics.len() == 1,
            "double resolve count",
            1,
            diagnostics.len()
        );
        crate::assert_with_log!(
            diagnostics[0].code == DiagnosticCode::DoubleResolve,
            "diagnostic code",
            DiagnosticCode::DoubleResolve,
            diagnostics[0].code
        );

        let result = validator.finish();
        crate::assert_with_log!(
            result.double_resolves().len() == 1,
            "final double resolve count",
            1,
            result.double_resolves().len()
        );
        crate::assert_with_log!(
            result.leaks().is_empty(),
            "no leaks",
            true,
            result.leaks().len()
        );
        crate::test_complete!("runtime_validator_detects_double_resolve_on_live_path");
    }

    #[test]
    fn runtime_validator_detects_scope_exit_leak() {
        init_test("runtime_validator_detects_scope_exit_leak");
        let var = v(1);
        let mut validator = RuntimeObligationValidator::new("runtime_exit_leak");

        let diagnostics = validator.reserve(var, ObligationKind::Lease);
        crate::assert_with_log!(
            diagnostics.is_empty(),
            "reserve clean",
            true,
            diagnostics.len()
        );

        let result = validator.finish();
        let leaks = result.leaks();
        crate::assert_with_log!(leaks.len() == 1, "leak count", 1, leaks.len());
        crate::assert_with_log!(
            leaks[0].code == DiagnosticCode::LeakExitDefinite,
            "leak code",
            DiagnosticCode::LeakExitDefinite,
            leaks[0].code
        );
        crate::assert_with_log!(
            result.graded_budget.exit_outstanding_upper_bound == 1,
            "exit outstanding",
            1,
            result.graded_budget.exit_outstanding_upper_bound
        );
        crate::test_complete!("runtime_validator_detects_scope_exit_leak");
    }

    // ---- Definite leaks ----------------------------------------------------

    #[test]
    fn definite_leak_no_resolve() {
        init_test("definite_leak_no_resolve");
        let body = Body::new(
            "leaky_fn",
            vec![Instruction::Reserve {
                var: v(0),
                kind: ObligationKind::SendPermit,
            }],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::DefiniteLeak,
            "kind",
            "definite-leak",
            kind
        );
        let obl_kind = leaks[0].obligation_kind;
        crate::assert_with_log!(
            obl_kind == Some(ObligationKind::SendPermit),
            "obligation_kind",
            Some(ObligationKind::SendPermit),
            obl_kind
        );
        crate::test_complete!("definite_leak_no_resolve");
    }

    #[test]
    fn definite_leak_multiple_vars() {
        init_test("definite_leak_multiple_vars");
        let body = Body::new(
            "double_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::IoOp,
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 2, "leak count", 2, len);
        // Deterministic order: v0, v1.
        let var0 = leaks[0].var;
        crate::assert_with_log!(var0 == v(0), "var0", v(0), var0);
        let var1 = leaks[1].var;
        crate::assert_with_log!(var1 == v(1), "var1", v(1), var1);
        crate::test_complete!("definite_leak_multiple_vars");
    }

    // ---- Potential leaks (branch-dependent) --------------------------------

    #[test]
    fn potential_leak_one_arm_missing_resolve() {
        init_test("potential_leak_one_arm");
        let body = Body::new(
            "branch_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Ack,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![], // No resolve in this arm.
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "kind",
            "potential-leak",
            kind
        );
        crate::test_complete!("potential_leak_one_arm");
    }

    #[test]
    fn potential_leak_three_arms_one_missing() {
        init_test("potential_leak_three_arms");
        let body = Body::new(
            "match_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                        vec![], // Missing resolve.
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "kind",
            "potential-leak",
            kind
        );
        crate::test_complete!("potential_leak_three_arms");
    }

    // ---- Double resolve ----------------------------------------------------

    #[test]
    fn double_resolve_detected() {
        init_test("double_resolve_detected");
        let body = Body::new(
            "double_resolve",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Commit { var: v(0) },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let doubles = result.double_resolves();
        let len = doubles.len();
        crate::assert_with_log!(len == 1, "double count", 1, len);
        let leaks = result.leaks();
        let leak_len = leaks.len();
        crate::assert_with_log!(leak_len == 0, "no leaks", 0, leak_len);
        crate::test_complete!("double_resolve_detected");
    }

    #[test]
    fn double_resolve_after_branch_commit_detected() {
        init_test("double_resolve_after_branch_commit_detected");
        let body = Body::new(
            "branch_double_commit",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![], // Untouched in this arm => MayHold after join.
                    ],
                },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let doubles = result.double_resolves();
        let len = doubles.len();
        crate::assert_with_log!(len == 1, "double count", 1, len);
        crate::assert_with_log!(
            doubles[0].code == DiagnosticCode::DoubleResolve,
            "code",
            DiagnosticCode::DoubleResolve,
            doubles[0].code
        );
        crate::assert_with_log!(
            doubles[0].kind == DiagnosticKind::DoubleResolve,
            "kind",
            DiagnosticKind::DoubleResolve,
            doubles[0].kind
        );
        let leaks = result.leaks();
        let leak_len = leaks.len();
        crate::assert_with_log!(leak_len == 0, "no leaks", 0, leak_len);
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        crate::test_complete!("double_resolve_after_branch_commit_detected");
    }

    #[test]
    fn double_resolve_after_branch_abort_detected() {
        init_test("double_resolve_after_branch_abort_detected");
        let body = Body::new(
            "branch_double_abort",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Abort { var: v(0) }],
                        vec![], // Untouched in this arm => MayHold after join.
                    ],
                },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let doubles = result.double_resolves();
        let len = doubles.len();
        crate::assert_with_log!(len == 1, "double count", 1, len);
        crate::assert_with_log!(
            doubles[0].code == DiagnosticCode::DoubleResolve,
            "code",
            DiagnosticCode::DoubleResolve,
            doubles[0].code
        );
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        crate::test_complete!("double_resolve_after_branch_abort_detected");
    }

    /// Fresh-eyes review of 54136c00c (27bbrg C2-M1): the doubt that a
    /// may-hold variable was already resolved survives an enclosing join. The
    /// inner branch may commit v0; the outer arm that contains it leaves v0
    /// may-hold without resolving it itself, so only the carried doubt
    /// reports the final commit as a double resolve.
    #[test]
    fn double_resolve_doubt_survives_an_enclosing_branch() {
        init_test("double_resolve_doubt_survives_an_enclosing_branch");
        let body = Body::new(
            "nested_branch_double_commit",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Branch {
                            arms: vec![vec![Instruction::Commit { var: v(0) }], vec![]],
                        }],
                        vec![],
                    ],
                },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let len = result.double_resolves().len();
        crate::assert_with_log!(len == 1, "double count", 1, len);
        let leak_len = result.leaks().len();
        crate::assert_with_log!(leak_len == 0, "no leaks", 0, leak_len);
        crate::test_complete!("double_resolve_doubt_survives_an_enclosing_branch");
    }

    // ---- Resolve unheld ----------------------------------------------------

    /// Review r28-e8 of 20d6e522f (27bbrg C2-M1): a branch that reserves a
    /// different kind on each path, then one commit, settles exactly one live
    /// obligation; it is clean, as in v0.4.3, not a double resolve.
    #[test]
    fn branch_reserving_different_kinds_then_one_commit_is_clean() {
        init_test("branch_reserving_different_kinds_then_one_commit_is_clean");
        let body = Body::new(
            "branch_kinds_then_commit",
            vec![
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Reserve {
                            var: v(0),
                            kind: ObligationKind::SendPermit,
                        }],
                        vec![Instruction::Reserve {
                            var: v(0),
                            kind: ObligationKind::IoOp,
                        }],
                    ],
                },
                Instruction::Commit { var: v(0) },
            ],
        );
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let doubles = result.double_resolves().len();
        crate::assert_with_log!(doubles == 0, "no double resolve", 0, doubles);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("branch_reserving_different_kinds_then_one_commit_is_clean");
    }

    #[test]
    fn resolve_unheld_detected() {
        init_test("resolve_unheld_detected");
        let body = Body::new("resolve_unheld", vec![Instruction::Commit { var: v(0) }]);

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        let first_kind = &result.diagnostics[0].kind;
        crate::assert_with_log!(
            *first_kind == DiagnosticKind::ResolveUnheld,
            "kind",
            "resolve-unheld",
            first_kind
        );
        crate::test_complete!("resolve_unheld_detected");
    }

    // ---- Overwrite leak (reserve over held) --------------------------------

    #[test]
    fn overwrite_leak_detected() {
        init_test("overwrite_leak_detected");
        let body = Body::new(
            "overwrite",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                // Overwrite without resolving first.
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        // Should detect the overwrite-leak.
        let leak_count = result
            .diagnostics
            .iter()
            .filter(|d| d.kind == DiagnosticKind::DefiniteLeak)
            .count();
        crate::assert_with_log!(leak_count == 1, "overwrite leak", 1, leak_count);
        // The second obligation is committed, so no exit leak.
        crate::test_complete!("overwrite_leak_detected");
    }

    #[test]
    fn overwrite_after_mayhold_is_potential_leak() {
        init_test("overwrite_after_mayhold_is_potential_leak");
        let body = Body::new(
            "overwrite_mayhold",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![vec![Instruction::Commit { var: v(0) }], vec![]],
                },
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);

        let potential_count = result
            .diagnostics
            .iter()
            .filter(|d| d.kind == DiagnosticKind::PotentialLeak)
            .count();
        let definite_count = result
            .diagnostics
            .iter()
            .filter(|d| d.kind == DiagnosticKind::DefiniteLeak)
            .count();

        crate::assert_with_log!(
            potential_count == 1,
            "potential overwrite leak",
            1,
            potential_count
        );
        crate::assert_with_log!(definite_count == 0, "no definite leak", 0, definite_count);
        crate::test_complete!("overwrite_after_mayhold_is_potential_leak");
    }

    // ---- Nested branches ---------------------------------------------------

    #[test]
    fn nested_branch_clean() {
        init_test("nested_branch_clean");
        let body = Body::new(
            "nested_clean",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Branch {
                            arms: vec![
                                vec![Instruction::Commit { var: v(0) }],
                                vec![Instruction::Abort { var: v(0) }],
                            ],
                        }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("nested_branch_clean");
    }

    #[test]
    fn nested_branch_leak() {
        init_test("nested_branch_leak");
        let body = Body::new(
            "nested_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Branch {
                            arms: vec![
                                vec![Instruction::Commit { var: v(0) }],
                                vec![], // Nested leak path.
                            ],
                        }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "kind",
            "potential-leak",
            kind
        );
        crate::test_complete!("nested_branch_leak");
    }

    // ---- Realistic: channel send permit pattern ----------------------------

    #[test]
    fn realistic_channel_send_permit() {
        init_test("realistic_channel_send_permit");
        // Models the two-phase send pattern:
        //   let permit = channel.reserve_send();  // Reserve
        //   if condition {
        //     permit.send(data);                  // Commit
        //   } else {
        //     permit.cancel();                    // Abort
        //   }
        let body = Body::new(
            "channel_send",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean send permit", true, is_clean);
        crate::test_complete!("realistic_channel_send_permit");
    }

    #[test]
    fn realistic_leaky_send_permit() {
        init_test("realistic_leaky_send_permit");
        // Models a buggy pattern where the error path forgets to cancel:
        //   let permit = channel.reserve_send();
        //   if ok {
        //     permit.send(data);
        //   } else {
        //     log_error();  // EXAMPLE BUG: forgot to cancel permit
        //   }
        let body = Body::new(
            "leaky_send",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![], // Bug: no cancel on error path.
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "kind",
            "potential-leak",
            kind
        );
        tracing::debug!(result = %result, "leak checker result");
        crate::test_complete!("realistic_leaky_send_permit");
    }

    // ---- Realistic: I/O operation with timeout and cancel ------------------

    #[test]
    fn realistic_io_with_timeout() {
        init_test("realistic_io_with_timeout");
        // Models:
        //   let io = reserve_io();
        //   match race(io_complete, timeout) {
        //     IoComplete => io.commit(),
        //     Timeout => io.abort(),
        //     Cancel => io.abort(),
        //   }
        let body = Body::new(
            "io_timeout",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![Instruction::Commit { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("realistic_io_with_timeout");
    }

    // ---- Realistic: lease with nested region close -------------------------

    #[test]
    fn realistic_lease_pattern() {
        init_test("realistic_lease_pattern");
        // Models a lease pattern with multiple obligations:
        //   let lease = acquire_lease();         // v0: Lease
        //   let ack = receive_message();          // v1: Ack
        //   process(data);
        //   ack.acknowledge();                    // commit v1
        //   lease.release();                      // commit v0
        let body = Body::new(
            "lease_and_ack",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::Ack,
                },
                Instruction::Commit { var: v(1) },
                Instruction::Commit { var: v(0) },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("realistic_lease_pattern");
    }

    #[test]
    fn realistic_lease_leak_on_error() {
        init_test("realistic_lease_leak_on_error");
        // Models a buggy lease pattern: error during processing leaks the lease.
        //   let lease = acquire_lease();         // v0: Lease
        //   let ack = receive_message();          // v1: Ack
        //   if error {
        //     ack.reject();                       // abort v1
        //     // EXAMPLE BUG: forgot to release lease
        //   } else {
        //     process(data);
        //     ack.acknowledge();                  // commit v1
        //     lease.release();                    // commit v0
        //   }
        let body = Body::new(
            "lease_error_leak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::Lease,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::Ack,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![
                            Instruction::Abort { var: v(1) },
                            // BUG: v0 not resolved.
                        ],
                        vec![
                            Instruction::Commit { var: v(1) },
                            Instruction::Commit { var: v(0) },
                        ],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 1, "leak count", 1, len);
        let leaked_var = leaks[0].var;
        crate::assert_with_log!(leaked_var == v(0), "leaked var", v(0), leaked_var);
        let leaked_kind = leaks[0].obligation_kind;
        crate::assert_with_log!(
            leaked_kind == Some(ObligationKind::Lease),
            "leaked kind",
            Some(ObligationKind::Lease),
            leaked_kind
        );
        tracing::debug!(result = %result, "leak checker result");
        crate::test_complete!("realistic_lease_leak_on_error");
    }

    // ---- Checker reuse -----------------------------------------------------

    #[test]
    fn checker_reuse_across_bodies() {
        init_test("checker_reuse_across_bodies");
        let mut checker = LeakChecker::new();

        let clean_body = Body::new(
            "clean",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Commit { var: v(0) },
            ],
        );
        let r1 = checker.check(&clean_body);
        let is_clean = r1.is_clean();
        crate::assert_with_log!(is_clean, "first clean", true, is_clean);

        let leaky_body = Body::new(
            "leaky",
            vec![Instruction::Reserve {
                var: v(0),
                kind: ObligationKind::Lease,
            }],
        );
        let r2 = checker.check(&leaky_body);
        let is_clean2 = r2.is_clean();
        crate::assert_with_log!(!is_clean2, "second leaky", false, is_clean2);

        // Check that first result was not contaminated.
        let first_leaks = r1.leaks().len();
        crate::assert_with_log!(first_leaks == 0, "first still clean", 0, first_leaks);
        crate::test_complete!("checker_reuse_across_bodies");
    }

    // ---- Deterministic output ----------------------------------------------

    #[test]
    fn deterministic_diagnostic_order() {
        init_test("deterministic_diagnostic_order");
        // Multiple leaks should be reported in variable-index order.
        let body = Body::new(
            "multi_leak",
            vec![
                Instruction::Reserve {
                    var: v(2),
                    kind: ObligationKind::IoOp,
                },
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::Lease,
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        let len = leaks.len();
        crate::assert_with_log!(len == 3, "leak count", 3, len);
        let vars: Vec<u32> = leaks.iter().map(|d| d.var.0).collect();
        crate::assert_with_log!(vars == vec![0, 1, 2], "order", vec![0u32, 1, 2], vars);
        crate::test_complete!("deterministic_diagnostic_order");
    }

    #[test]
    fn diagnostic_metadata_is_stable() {
        init_test("diagnostic_metadata_is_stable");
        let body = Body::new("metadata", vec![Instruction::Commit { var: v(0) }]);

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let diag = &result.diagnostics[0];

        crate::assert_with_log!(
            diag.code == DiagnosticCode::ResolveUnheld,
            "machine code",
            DiagnosticCode::ResolveUnheld,
            diag.code
        );
        crate::assert_with_log!(
            diag.location.kind == DiagnosticLocationKind::Instruction,
            "location kind",
            DiagnosticLocationKind::Instruction,
            diag.location.kind
        );
        crate::assert_with_log!(
            diag.location.instruction_path == vec![0usize],
            "instruction path",
            vec![0usize],
            diag.location.instruction_path.clone()
        );
        crate::assert_with_log!(
            !diag.remediation_hint.is_empty(),
            "remediation hint",
            true,
            !diag.remediation_hint.is_empty()
        );
        crate::test_complete!("diagnostic_metadata_is_stable");
    }

    #[test]
    fn graded_budget_summary_tracks_restricted_ir_peak() {
        init_test("graded_budget_summary_tracks_restricted_ir_peak");
        let body = Body::new(
            "budget_peak",
            vec![
                Instruction::Reserve {
                    var: v(0),
                    kind: ObligationKind::SendPermit,
                },
                Instruction::Reserve {
                    var: v(1),
                    kind: ObligationKind::Ack,
                },
                Instruction::Branch {
                    arms: vec![
                        vec![
                            Instruction::Commit { var: v(0) },
                            Instruction::Commit { var: v(1) },
                        ],
                        vec![Instruction::Abort { var: v(0) }],
                    ],
                },
            ],
        );

        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let budget = &result.graded_budget;

        crate::assert_with_log!(
            budget.conservative_peak_outstanding == 2,
            "peak outstanding",
            2usize,
            budget.conservative_peak_outstanding
        );
        crate::assert_with_log!(
            budget.exit_outstanding_upper_bound == 1,
            "exit upper bound",
            1usize,
            budget.exit_outstanding_upper_bound
        );
        crate::assert_with_log!(
            budget
                .peak_outstanding_by_kind
                .get(&ObligationKind::SendPermit)
                == Some(&1),
            "send peak",
            Some(&1usize),
            budget
                .peak_outstanding_by_kind
                .get(&ObligationKind::SendPermit)
        );
        crate::assert_with_log!(
            budget.peak_outstanding_by_kind.get(&ObligationKind::Ack) == Some(&1),
            "ack peak",
            Some(&1usize),
            budget.peak_outstanding_by_kind.get(&ObligationKind::Ack)
        );
        crate::test_complete!("graded_budget_summary_tracks_restricted_ir_peak");
    }

    #[test]
    fn static_leak_check_contract_is_explicit() {
        init_test("static_leak_check_contract_is_explicit");
        let contract = static_leak_check_contract();

        crate::assert_with_log!(
            contract.supported_instructions == ["Reserve", "Commit", "Abort", "Branch"],
            "supported instructions",
            vec!["Reserve", "Commit", "Abort", "Branch"],
            contract.supported_instructions.to_vec()
        );
        crate::assert_with_log!(
            contract
                .runtime_oracles
                .contains(&"src/obligation/no_leak_proof.rs"),
            "runtime oracle anchor",
            true,
            contract
                .runtime_oracles
                .contains(&"src/obligation/no_leak_proof.rs")
        );
        crate::assert_with_log!(
            contract
                .out_of_scope_patterns
                .iter()
                .any(|pattern| pattern.contains("Drop-based cleanup")),
            "out-of-scope contract",
            true,
            contract
                .out_of_scope_patterns
                .iter()
                .any(|pattern| pattern.contains("Drop-based cleanup"))
        );
        crate::test_complete!("static_leak_check_contract_is_explicit");
    }

    // ---- Display impls -----------------------------------------------------

    #[test]
    fn display_impls() {
        init_test("display_impls");
        let var = ObligationVar(42);
        let var_str = format!("{var}");
        crate::assert_with_log!(var_str == "v42", "var display", "v42", var_str);

        let state = VarState::Held(ObligationKind::SendPermit);
        let state_str = format!("{state}");
        crate::assert_with_log!(
            state_str == "held(send_permit)",
            "state display",
            "held(send_permit)",
            state_str
        );

        let diag = Diagnostic {
            code: DiagnosticCode::LeakExitDefinite,
            kind: DiagnosticKind::DefiniteLeak,
            var: ObligationVar(0),
            obligation_kind: Some(ObligationKind::SendPermit),
            location: DiagnosticLocation::scope_exit(),
            scope: "test_fn".to_string(),
            remediation_hint: DiagnosticCode::LeakExitDefinite.remediation_hint(),
            message: "v0 leaked".to_string(),
        };
        let diag_str = format!("{diag}");
        let has_fn = diag_str.contains("test_fn");
        crate::assert_with_log!(has_fn, "diag has scope", true, has_fn);
        let has_kind = diag_str.contains("definite-leak");
        crate::assert_with_log!(has_kind, "diag has kind", true, has_kind);
        let has_code = diag_str.contains(DiagnosticCode::LeakExitDefinite.as_str());
        crate::assert_with_log!(has_code, "diag has code", true, has_code);
        crate::test_complete!("display_impls");
    }

    // ---- VarState lattice join exhaustive ----------------------------------

    #[test]
    fn var_state_join_lattice() {
        init_test("var_state_join_lattice");
        let k = ObligationKind::SendPermit;
        let k2 = ObligationKind::IoOp;

        // Identity.
        let r = VarState::Empty.join(VarState::Empty);
        crate::assert_with_log!(r == VarState::Empty, "e+e", VarState::Empty, r);
        let r = VarState::Resolved.join(VarState::Resolved);
        crate::assert_with_log!(r == VarState::Resolved, "r+r", VarState::Resolved, r);
        let r = VarState::Held(k).join(VarState::Held(k));
        crate::assert_with_log!(r == VarState::Held(k), "h+h", VarState::Held(k), r);

        // Held + Resolved => MayHold.
        let r = VarState::Held(k).join(VarState::Resolved);
        crate::assert_with_log!(r == VarState::MayHold(k), "h+r", VarState::MayHold(k), r);

        // Held + Empty => MayHold.
        let r = VarState::Held(k).join(VarState::Empty);
        crate::assert_with_log!(r == VarState::MayHold(k), "h+e", VarState::MayHold(k), r);

        // Resolved + Empty => Resolved.
        let r = VarState::Resolved.join(VarState::Empty);
        crate::assert_with_log!(r == VarState::Resolved, "r+e", VarState::Resolved, r);

        // MayHold propagates.
        let r = VarState::MayHold(k).join(VarState::Empty);
        crate::assert_with_log!(r == VarState::MayHold(k), "m+e", VarState::MayHold(k), r);
        let r = VarState::MayHold(k).join(VarState::Resolved);
        crate::assert_with_log!(r == VarState::MayHold(k), "m+r", VarState::MayHold(k), r);

        // Different kinds => MayHoldAmbiguous.
        let r = VarState::Held(k).join(VarState::Held(k2));
        crate::assert_with_log!(
            r == VarState::MayHoldAmbiguous,
            "h(k1)+h(k2)",
            VarState::MayHoldAmbiguous,
            r
        );

        // Commutativity check.
        let r1 = VarState::Held(k).join(VarState::Resolved);
        let r2 = VarState::Resolved.join(VarState::Held(k));
        crate::assert_with_log!(r1 == r2, "commutative", r1, r2);

        crate::test_complete!("var_state_join_lattice");
    }

    // ---- Empty body --------------------------------------------------------

    #[test]
    fn empty_body_is_clean() {
        init_test("empty_body_is_clean");
        let body = Body::new("empty", vec![]);
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let is_clean = result.is_clean();
        crate::assert_with_log!(is_clean, "clean", true, is_clean);
        crate::test_complete!("empty_body_is_clean");
    }

    // ---- CheckResult display -----------------------------------------------

    #[test]
    fn check_result_display() {
        init_test("check_result_display");
        let clean = CheckResult {
            scope: "clean_fn".to_string(),
            diagnostics: vec![],
            contract: static_leak_check_contract(),
            graded_budget: GradedBudgetSummary::default(),
        };
        let clean_str = format!("{clean}");
        let has_no_issues = clean_str.contains("no issues");
        crate::assert_with_log!(has_no_issues, "clean display", true, has_no_issues);

        let dirty = CheckResult {
            scope: "dirty_fn".to_string(),
            diagnostics: vec![Diagnostic {
                code: DiagnosticCode::LeakExitDefinite,
                kind: DiagnosticKind::DefiniteLeak,
                var: v(0),
                obligation_kind: Some(ObligationKind::SendPermit),
                location: DiagnosticLocation::scope_exit(),
                scope: "dirty_fn".to_string(),
                remediation_hint: DiagnosticCode::LeakExitDefinite.remediation_hint(),
                message: "test".to_string(),
            }],
            contract: static_leak_check_contract(),
            graded_budget: GradedBudgetSummary::default(),
        };
        let dirty_str = format!("{dirty}");
        let has_count = dirty_str.contains("1 diagnostic");
        crate::assert_with_log!(has_count, "dirty display", true, has_count);
        crate::test_complete!("check_result_display");
    }

    // ---- BodyBuilder -------------------------------------------------------

    #[test]
    fn builder_clean_reserve_commit() {
        init_test("builder_clean_reserve_commit");
        let mut b = BodyBuilder::new("clean");
        let v = b.reserve(ObligationKind::SendPermit);
        b.commit(v);
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::test_complete!("builder_clean_reserve_commit");
    }

    #[test]
    fn builder_leak_detected() {
        init_test("builder_leak_detected");
        let mut b = BodyBuilder::new("leaky");
        let _v = b.reserve(ObligationKind::Lease);
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        crate::assert_with_log!(leaks.len() == 1, "leak count", 1, leaks.len());
        crate::test_complete!("builder_leak_detected");
    }

    #[test]
    fn builder_branch_clean() {
        init_test("builder_branch_clean");
        let mut b = BodyBuilder::new("branch_clean");
        let v = b.reserve(ObligationKind::IoOp);
        b.branch(|bb| {
            bb.arm(|a| {
                a.commit(v);
            });
            bb.arm(|a| {
                a.abort(v);
            });
        });
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::test_complete!("builder_branch_clean");
    }

    #[test]
    fn builder_branch_potential_leak() {
        init_test("builder_branch_potential_leak");
        let mut b = BodyBuilder::new("branch_leak");
        let v = b.reserve(ObligationKind::Ack);
        b.branch(|bb| {
            bb.arm(|a| {
                a.commit(v);
            });
            bb.arm(|_a| {}); // Missing resolution.
        });
        let body = b.build();
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        let leaks = result.leaks();
        crate::assert_with_log!(leaks.len() == 1, "leak count", 1, leaks.len());
        let kind = &leaks[0].kind;
        crate::assert_with_log!(
            *kind == DiagnosticKind::PotentialLeak,
            "potential",
            DiagnosticKind::PotentialLeak,
            kind
        );
        crate::test_complete!("builder_branch_potential_leak");
    }

    #[test]
    fn builder_auto_var_numbering() {
        init_test("builder_auto_var_numbering");
        let mut b = BodyBuilder::new("auto_vars");
        let v0 = b.reserve(ObligationKind::SendPermit);
        let v1 = b.reserve(ObligationKind::Ack);
        let v2 = b.reserve(ObligationKind::Lease);
        crate::assert_with_log!(v0 == ObligationVar(0), "v0", ObligationVar(0), v0);
        crate::assert_with_log!(v1 == ObligationVar(1), "v1", ObligationVar(1), v1);
        crate::assert_with_log!(v2 == ObligationVar(2), "v2", ObligationVar(2), v2);
        b.commit(v0);
        b.commit(v1);
        b.commit(v2);
        let body = b.build();
        let mut checker = LeakChecker::new();
        crate::assert_with_log!(
            checker.check(&body).is_clean(),
            "clean",
            true,
            checker.check(&body).is_clean()
        );
        crate::test_complete!("builder_auto_var_numbering");
    }

    #[test]
    fn builder_nested_branch() {
        init_test("builder_nested_branch");
        let mut b = BodyBuilder::new("nested");
        let v = b.reserve(ObligationKind::SendPermit);
        b.branch(|bb| {
            bb.arm(|a| {
                a.branch(|bb2| {
                    bb2.arm(|a2| {
                        a2.commit(v);
                    });
                    bb2.arm(|a2| {
                        a2.abort(v);
                    });
                });
            });
            bb.arm(|a| {
                a.abort(v);
            });
        });
        let body = b.build();
        let mut checker = LeakChecker::new();
        crate::assert_with_log!(
            checker.check(&body).is_clean(),
            "clean",
            true,
            checker.check(&body).is_clean()
        );
        crate::test_complete!("builder_nested_branch");
    }

    // ---- ObligationAnalyzer ------------------------------------------------

    #[test]
    fn analyzer_clean() {
        init_test("analyzer_clean");
        let mut a = ObligationAnalyzer::new("clean_scope");
        let v = a.reserve(ObligationKind::SendPermit);
        a.commit(v);
        a.assert_clean();
        crate::test_complete!("analyzer_clean");
    }

    #[test]
    fn analyzer_detects_leak() {
        init_test("analyzer_detects_leak");
        let mut a = ObligationAnalyzer::new("leaky_scope");
        let _v = a.reserve(ObligationKind::Lease);
        a.assert_leaks(1);
        crate::test_complete!("analyzer_detects_leak");
    }

    #[test]
    fn analyzer_branch_clean() {
        init_test("analyzer_branch_clean");
        let mut a = ObligationAnalyzer::new("branch_scope");
        let v = a.reserve(ObligationKind::IoOp);
        a.branch(|bb| {
            bb.arm(|arm| {
                arm.commit(v);
            });
            bb.arm(|arm| {
                arm.abort(v);
            });
        });
        a.assert_clean();
        crate::test_complete!("analyzer_branch_clean");
    }

    #[test]
    fn analyzer_branch_leak() {
        init_test("analyzer_branch_leak");
        let mut a = ObligationAnalyzer::new("branch_leak");
        let v = a.reserve(ObligationKind::Ack);
        a.branch(|bb| {
            bb.arm(|arm| {
                arm.commit(v);
            });
            bb.arm(|_arm| {}); // Missing.
        });
        a.assert_leaks(1);
        crate::test_complete!("analyzer_branch_leak");
    }

    // ---- Macros ------------------------------------------------------------

    #[test]
    fn macro_obligation_body_clean() {
        init_test("macro_obligation_body_clean");
        let body = crate::obligation_body!("macro_clean", |b| {
            let v = b.reserve(ObligationKind::SendPermit);
            b.commit(v);
        });
        let mut checker = LeakChecker::new();
        let result = checker.check(&body);
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::test_complete!("macro_obligation_body_clean");
    }

    #[test]
    fn macro_assert_no_leaks_inline() {
        init_test("macro_assert_no_leaks_inline");
        crate::assert_no_leaks!("inline_clean", |b| {
            let v = b.reserve(ObligationKind::SendPermit);
            b.commit(v);
        });
        crate::test_complete!("macro_assert_no_leaks_inline");
    }

    #[test]
    fn macro_assert_has_leaks() {
        init_test("macro_assert_has_leaks");
        let body = crate::obligation_body!("leaky_macro", |b| {
            let _v = b.reserve(ObligationKind::Lease);
        });
        crate::assert_has_leaks!(body, 1);
        crate::test_complete!("macro_assert_has_leaks");
    }

    #[test]
    fn macro_assert_no_leaks_body() {
        init_test("macro_assert_no_leaks_body");
        let body = crate::obligation_body!("body_clean", |b| {
            let v = b.reserve(ObligationKind::Ack);
            b.abort(v);
        });
        crate::assert_no_leaks!(body);
        crate::test_complete!("macro_assert_no_leaks_body");
    }
