//! E2E integration tests for the static obligation leak checker.
//!
//! Tests the full integration path: BodyBuilder, ObligationAnalyzer,
//! `obligation_body!` / `assert_no_leaks!` / `assert_has_leaks!` macros,
//! and realistic obligation patterns (channel sends, lease/ack combos,
//! I/O with timeout, cancellation).

mod common;
use common::*;

use asupersync::obligation::{
    BodyBuilder, DiagnosticKind, LeakChecker, ObligationAnalyzer, ObligationVar,
};
use asupersync::record::ObligationKind;
use asupersync::{assert_has_leaks, assert_no_leaks, obligation_body};

// ==================== BodyBuilder Integration ====================

#[test]
fn e2e_body_builder_clean_single_obligation() {
    init_test_logging();
    test_phase!("e2e_body_builder_clean_single_obligation");

    let mut b = BodyBuilder::new("single_clean");
    let v = b.reserve(ObligationKind::SendPermit);
    b.commit(v);
    let body = b.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    assert!(
        result.is_clean(),
        "single obligation with commit should be clean"
    );
    assert!(result.leaks().is_empty());
    assert!(result.double_resolves().is_empty());

    test_complete!("e2e_body_builder_clean_single_obligation");
}

#[test]
fn e2e_body_builder_clean_multi_obligation() {
    init_test_logging();
    test_phase!("e2e_body_builder_clean_multi_obligation");

    let mut b = BodyBuilder::new("multi_clean");
    let send = b.reserve(ObligationKind::SendPermit);
    let ack = b.reserve(ObligationKind::Ack);
    let lease = b.reserve(ObligationKind::Lease);
    let io = b.reserve(ObligationKind::IoOp);
    b.commit(send);
    b.commit(ack);
    b.abort(lease);
    b.commit(io);
    let body = b.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    assert!(result.is_clean(), "all four kinds resolved should be clean");

    test_complete!("e2e_body_builder_clean_multi_obligation");
}

#[test]
fn e2e_body_builder_definite_leak() {
    init_test_logging();
    test_phase!("e2e_body_builder_definite_leak");

    let mut b = BodyBuilder::new("definite_leak");
    let _send = b.reserve(ObligationKind::SendPermit);
    let _io = b.reserve(ObligationKind::IoOp);
    let body = b.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    assert!(!result.is_clean());

    let leaks = result.leaks();
    assert_eq!(leaks.len(), 2, "both obligations should be leaked");
    assert!(leaks.iter().all(|d| d.kind == DiagnosticKind::DefiniteLeak));

    // Verify obligation kinds are tracked.
    let kinds: Vec<_> = leaks.iter().filter_map(|d| d.obligation_kind).collect();
    assert!(kinds.contains(&ObligationKind::SendPermit));
    assert!(kinds.contains(&ObligationKind::IoOp));

    test_complete!("e2e_body_builder_definite_leak");
}

#[test]
fn e2e_body_builder_branch_both_arms_resolve() {
    init_test_logging();
    test_phase!("e2e_body_builder_branch_both_arms_resolve");

    let mut b = BodyBuilder::new("branch_both_resolve");
    let v = b.reserve(ObligationKind::SendPermit);
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
    assert!(checker.check(&body).is_clean());

    test_complete!("e2e_body_builder_branch_both_arms_resolve");
}

#[test]
fn e2e_body_builder_branch_one_arm_missing() {
    init_test_logging();
    test_phase!("e2e_body_builder_branch_one_arm_missing");

    let mut b = BodyBuilder::new("branch_missing_arm");
    let v = b.reserve(ObligationKind::Ack);
    b.branch(|bb| {
        bb.arm(|a| {
            a.commit(v);
        });
        bb.arm(|_a| {}); // Error path forgets to cancel.
    });
    let body = b.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    let leaks = result.leaks();
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].kind, DiagnosticKind::PotentialLeak);
    assert_eq!(leaks[0].obligation_kind, Some(ObligationKind::Ack));

    test_complete!("e2e_body_builder_branch_one_arm_missing");
}

#[test]
fn e2e_body_builder_three_way_branch_one_leak() {
    init_test_logging();
    test_phase!("e2e_body_builder_three_way_branch_one_leak");

    let mut b = BodyBuilder::new("three_way");
    let v = b.reserve(ObligationKind::Lease);
    b.branch(|bb| {
        bb.arm(|a| {
            a.commit(v);
        }); // Success.
        bb.arm(|a| {
            a.abort(v);
        }); // Timeout.
        bb.arm(|_a| {}); // Cancel — forgets to abort.
    });
    let body = b.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    assert_eq!(result.leaks().len(), 1);

    test_complete!("e2e_body_builder_three_way_branch_one_leak");
}

#[test]
fn e2e_body_builder_nested_branches_clean() {
    init_test_logging();
    test_phase!("e2e_body_builder_nested_branches_clean");

    let mut b = BodyBuilder::new("nested_clean");
    let v = b.reserve(ObligationKind::IoOp);
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
    assert!(checker.check(&body).is_clean());

    test_complete!("e2e_body_builder_nested_branches_clean");
}

#[test]
fn e2e_body_builder_nested_branches_deep_leak() {
    init_test_logging();
    test_phase!("e2e_body_builder_nested_branches_deep_leak");

    let mut b = BodyBuilder::new("nested_leak");
    let v = b.reserve(ObligationKind::Lease);
    b.branch(|bb| {
        bb.arm(|a| {
            a.branch(|bb2| {
                bb2.arm(|a2| {
                    a2.commit(v);
                });
                bb2.arm(|_a2| {}); // Deep leak path.
            });
        });
        bb.arm(|a| {
            a.abort(v);
        });
    });
    let body = b.build();

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    assert_eq!(result.leaks().len(), 1);
    assert_eq!(result.leaks()[0].kind, DiagnosticKind::PotentialLeak);

    test_complete!("e2e_body_builder_nested_branches_deep_leak");
}

// ==================== ObligationAnalyzer Integration ====================

#[test]
fn e2e_analyzer_clean_scope() {
    init_test_logging();
    test_phase!("e2e_analyzer_clean_scope");

    let mut a = ObligationAnalyzer::new("clean_handler");
    let permit = a.reserve(ObligationKind::SendPermit);
    let ack = a.reserve(ObligationKind::Ack);
    a.commit(permit);
    a.abort(ack);
    a.assert_clean();

    test_complete!("e2e_analyzer_clean_scope");
}

#[test]
fn e2e_analyzer_leak_detection() {
    init_test_logging();
    test_phase!("e2e_analyzer_leak_detection");

    let mut a = ObligationAnalyzer::new("leaky_handler");
    let _permit = a.reserve(ObligationKind::SendPermit);
    // Forgot to commit or abort.
    a.assert_leaks(1);

    test_complete!("e2e_analyzer_leak_detection");
}

#[test]
fn e2e_analyzer_branch_with_check() {
    init_test_logging();
    test_phase!("e2e_analyzer_branch_with_check");

    let mut a = ObligationAnalyzer::new("branch_handler");
    let lease = a.reserve(ObligationKind::Lease);
    a.branch(|bb| {
        bb.arm(|arm| {
            arm.commit(lease);
        });
        bb.arm(|arm| {
            arm.abort(lease);
        });
    });

    let result = a.check();
    assert!(result.is_clean());
    assert_eq!(result.scope, "branch_handler");

    test_complete!("e2e_analyzer_branch_with_check");
}

#[test]
fn e2e_analyzer_double_resolve() {
    init_test_logging();
    test_phase!("e2e_analyzer_double_resolve");

    let mut a = ObligationAnalyzer::new("double_resolve");
    let v = a.reserve(ObligationKind::SendPermit);
    a.commit(v);
    a.commit(v); // Bug: double commit.

    let result = a.check();
    let doubles = result.double_resolves();
    assert_eq!(doubles.len(), 1);
    assert_eq!(doubles[0].kind, DiagnosticKind::DoubleResolve);

    test_complete!("e2e_analyzer_double_resolve");
}

// ==================== Macro Integration ====================

#[test]
fn e2e_macro_obligation_body_clean() {
    init_test_logging();
    test_phase!("e2e_macro_obligation_body_clean");

    let body = obligation_body!("macro_clean", |b| {
        let v = b.reserve(ObligationKind::SendPermit);
        b.commit(v);
    });

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    assert!(result.is_clean());

    test_complete!("e2e_macro_obligation_body_clean");
}

#[test]
fn e2e_macro_obligation_body_with_branch() {
    init_test_logging();
    test_phase!("e2e_macro_obligation_body_with_branch");

    let body = obligation_body!("macro_branch", |b| {
        let v = b.reserve(ObligationKind::IoOp);
        b.branch(|bb| {
            bb.arm(|a| {
                a.commit(v);
            });
            bb.arm(|a| {
                a.abort(v);
            });
        });
    });

    let mut checker = LeakChecker::new();
    assert!(checker.check(&body).is_clean());

    test_complete!("e2e_macro_obligation_body_with_branch");
}

#[test]
fn e2e_macro_assert_no_leaks_passes_on_clean() {
    init_test_logging();
    test_phase!("e2e_macro_assert_no_leaks_passes_on_clean");

    // Inline form.
    assert_no_leaks!("inline_clean", |b| {
        let v = b.reserve(ObligationKind::SendPermit);
        b.commit(v);
    });

    // Body form.
    let body = obligation_body!("body_clean", |b| {
        let v = b.reserve(ObligationKind::Ack);
        b.abort(v);
    });
    assert_no_leaks!(body);

    test_complete!("e2e_macro_assert_no_leaks_passes_on_clean");
}

#[test]
fn e2e_macro_assert_has_leaks_catches_leak() {
    init_test_logging();
    test_phase!("e2e_macro_assert_has_leaks_catches_leak");

    let body = obligation_body!("leaky", |b| {
        let _v = b.reserve(ObligationKind::Lease);
    });
    assert_has_leaks!(body, 1);

    // Multiple leaks.
    let body2 = obligation_body!("double_leak", |b| {
        let _v1 = b.reserve(ObligationKind::SendPermit);
        let _v2 = b.reserve(ObligationKind::IoOp);
    });
    assert_has_leaks!(body2, 2);

    test_complete!("e2e_macro_assert_has_leaks_catches_leak");
}

// ==================== Realistic Patterns ====================

#[test]
fn e2e_realistic_channel_two_phase_send() {
    init_test_logging();
    test_phase!("e2e_realistic_channel_two_phase_send");

    // Correct pattern: reserve → branch(commit/abort)
    assert_no_leaks!("channel_send_correct", |b| {
        let permit = b.reserve(ObligationKind::SendPermit);
        b.branch(|bb| {
            bb.arm(|a| {
                a.commit(permit);
            }); // Send succeeds.
            bb.arm(|a| {
                a.abort(permit);
            }); // Channel full → cancel.
        });
    });

    // Buggy pattern: error path forgets to cancel permit.
    let buggy = obligation_body!("channel_send_buggy", |b| {
        let permit = b.reserve(ObligationKind::SendPermit);
        b.branch(|bb| {
            bb.arm(|a| {
                a.commit(permit);
            });
            bb.arm(|_a| {}); // Bug: forgot to cancel.
        });
    });
    assert_has_leaks!(buggy, 1);

    test_complete!("e2e_realistic_channel_two_phase_send");
}

#[test]
fn e2e_realistic_io_with_timeout_and_cancel() {
    init_test_logging();
    test_phase!("e2e_realistic_io_with_timeout_and_cancel");

    // race(io_complete, timeout, cancel):
    assert_no_leaks!("io_timeout_cancel", |b| {
        let io = b.reserve(ObligationKind::IoOp);
        b.branch(|bb| {
            bb.arm(|a| {
                a.commit(io);
            }); // IoComplete.
            bb.arm(|a| {
                a.abort(io);
            }); // Timeout.
            bb.arm(|a| {
                a.abort(io);
            }); // Cancel.
        });
    });

    test_complete!("e2e_realistic_io_with_timeout_and_cancel");
}

#[test]
fn e2e_realistic_lease_and_ack_combo() {
    init_test_logging();
    test_phase!("e2e_realistic_lease_and_ack_combo");

    // Correct: both obligations resolved.
    assert_no_leaks!("lease_ack_correct", |b| {
        let lease = b.reserve(ObligationKind::Lease);
        let ack = b.reserve(ObligationKind::Ack);
        b.commit(ack);
        b.commit(lease);
    });

    // Buggy: error path resolves ack but leaks lease.
    let buggy = obligation_body!("lease_ack_buggy", |b| {
        let lease = b.reserve(ObligationKind::Lease);
        let ack = b.reserve(ObligationKind::Ack);
        b.branch(|bb| {
            bb.arm(|a| {
                a.abort(ack);
                // Bug: forgot to release lease.
            });
            bb.arm(|a| {
                a.commit(ack);
                a.commit(lease);
            });
        });
    });

    let mut checker = LeakChecker::new();
    let result = checker.check(&buggy);
    let leaks = result.leaks();
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].obligation_kind, Some(ObligationKind::Lease));

    test_complete!("e2e_realistic_lease_and_ack_combo");
}

#[test]
fn e2e_realistic_nested_region_close() {
    init_test_logging();
    test_phase!("e2e_realistic_nested_region_close");

    // Simulates closing a child region before parent:
    // - Reserve lease in child scope.
    // - Reserve ack in parent scope.
    // - Resolve both.
    assert_no_leaks!("nested_region", |b| {
        let parent_ack = b.reserve(ObligationKind::Ack);
        let child_lease = b.reserve(ObligationKind::Lease);
        // Child region close: resolve child's lease.
        b.commit(child_lease);
        // Parent region close: resolve parent's ack.
        b.commit(parent_ack);
    });

    test_complete!("e2e_realistic_nested_region_close");
}

#[test]
fn e2e_realistic_cancellation_handler() {
    init_test_logging();
    test_phase!("e2e_realistic_cancellation_handler");

    // Cancellation handler pattern:
    // 1. Reserve multiple obligations.
    // 2. On cancel, abort all.
    // 3. On success, commit all.
    assert_no_leaks!("cancel_handler", |b| {
        let send = b.reserve(ObligationKind::SendPermit);
        let io = b.reserve(ObligationKind::IoOp);
        b.branch(|bb| {
            bb.arm(|a| {
                // Success path: commit both.
                a.commit(send);
                a.commit(io);
            });
            bb.arm(|a| {
                // Cancel path: abort both.
                a.abort(send);
                a.abort(io);
            });
        });
    });

    test_complete!("e2e_realistic_cancellation_handler");
}

// ==================== Fix-on-Fix Demonstration ====================

#[test]
fn e2e_fix_on_fix_detect_then_repair() {
    init_test_logging();
    test_phase!("e2e_fix_on_fix_detect_then_repair");

    // Step 1: buggy code — error path leaks the lease.
    let buggy = obligation_body!("buggy_handler", |b| {
        let lease = b.reserve(ObligationKind::Lease);
        let ack = b.reserve(ObligationKind::Ack);
        b.branch(|bb| {
            bb.arm(|a| {
                // Error: reject ack but forget lease.
                a.abort(ack);
            });
            bb.arm(|a| {
                // Happy path: commit both.
                a.commit(ack);
                a.commit(lease);
            });
        });
    });

    let mut checker = LeakChecker::new();
    let buggy_result = checker.check(&buggy);
    assert!(!buggy_result.is_clean(), "buggy code should have leaks");
    assert_eq!(buggy_result.leaks().len(), 1);
    assert_eq!(
        buggy_result.leaks()[0].obligation_kind,
        Some(ObligationKind::Lease),
        "the leaked obligation should be the Lease"
    );

    // Step 2: fixed code — add abort(lease) on error path.
    let fixed = obligation_body!("fixed_handler", |b| {
        let lease = b.reserve(ObligationKind::Lease);
        let ack = b.reserve(ObligationKind::Ack);
        b.branch(|bb| {
            bb.arm(|a| {
                // Error: reject ack AND release lease.
                a.abort(ack);
                a.abort(lease); // Fix applied.
            });
            bb.arm(|a| {
                // Happy path: commit both.
                a.commit(ack);
                a.commit(lease);
            });
        });
    });

    let fixed_result = checker.check(&fixed);
    assert!(fixed_result.is_clean(), "fixed code should be clean");

    test_complete!("e2e_fix_on_fix_detect_then_repair");
}

// ==================== Edge Cases ====================

#[test]
fn e2e_empty_body_clean() {
    init_test_logging();
    test_phase!("e2e_empty_body_clean");

    let body = obligation_body!("empty", |_b| {});
    assert_no_leaks!(body);

    test_complete!("e2e_empty_body_clean");
}

#[test]
fn e2e_overwrite_detected() {
    init_test_logging();
    test_phase!("e2e_overwrite_detected");

    // Reserve on same var (via builder this is different vars, but demonstrate
    // the overwrite via raw Body).
    let body = asupersync::obligation::Body::new(
        "overwrite",
        vec![
            asupersync::obligation::Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::SendPermit,
            },
            // Overwrite v0 without resolving.
            asupersync::obligation::Instruction::Reserve {
                var: ObligationVar(0),
                kind: ObligationKind::IoOp,
            },
            asupersync::obligation::Instruction::Commit {
                var: ObligationVar(0),
            },
        ],
    );

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    // Should detect the overwrite as a definite leak.
    let definite = result
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagnosticKind::DefiniteLeak)
        .count();
    assert_eq!(
        definite, 1,
        "overwrite should produce exactly 1 definite leak"
    );

    test_complete!("e2e_overwrite_detected");
}

#[test]
fn e2e_checker_deterministic() {
    init_test_logging();
    test_phase!("e2e_checker_deterministic");

    let build = || {
        obligation_body!("determinism", |b| {
            let v0 = b.reserve(ObligationKind::SendPermit);
            let v1 = b.reserve(ObligationKind::Ack);
            b.branch(|bb| {
                bb.arm(|a| {
                    a.commit(v0);
                    a.commit(v1);
                });
                bb.arm(|a| {
                    a.abort(v0);
                }); // v1 leaked.
            });
        })
    };

    let mut checker = LeakChecker::new();
    let r1 = checker.check(&build());
    let r2 = checker.check(&build());

    assert_eq!(r1.diagnostics.len(), r2.diagnostics.len());
    for (a, b) in r1.diagnostics.iter().zip(r2.diagnostics.iter()) {
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.var, b.var);
        assert_eq!(a.obligation_kind, b.obligation_kind);
    }

    test_complete!("e2e_checker_deterministic");
}

#[test]
fn e2e_analyzer_all_four_obligation_kinds() {
    init_test_logging();
    test_phase!("e2e_analyzer_all_four_obligation_kinds");

    let mut a = ObligationAnalyzer::new("all_kinds");
    let send = a.reserve(ObligationKind::SendPermit);
    let ack = a.reserve(ObligationKind::Ack);
    let lease = a.reserve(ObligationKind::Lease);
    let io = a.reserve(ObligationKind::IoOp);
    a.commit(send);
    a.abort(ack);
    a.commit(lease);
    a.abort(io);
    a.assert_clean();

    test_complete!("e2e_analyzer_all_four_obligation_kinds");
}

#[test]
fn e2e_check_result_display_includes_scope() {
    init_test_logging();
    test_phase!("e2e_check_result_display_includes_scope");

    let body = obligation_body!("display_test", |b| {
        let _v = b.reserve(ObligationKind::Lease);
    });

    let mut checker = LeakChecker::new();
    let result = checker.check(&body);
    let text = format!("{result}");
    assert!(
        text.contains("display_test"),
        "display should include scope name"
    );
    assert!(
        text.contains("definite-leak"),
        "display should include diagnostic kind"
    );

    test_complete!("e2e_check_result_display_includes_scope");
}
