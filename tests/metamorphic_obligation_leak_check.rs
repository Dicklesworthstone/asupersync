#![allow(clippy::all)]
//! Metamorphic tests for obligation leak check reachability invariants.
//!
//! Tests mathematical properties of the static obligation leak checker through
//! metamorphic relations. Each relation verifies that certain transformations
//! preserve semantic equivalence or produce predictable changes.

use asupersync::obligation::{Body, Diagnostic, Instruction, LeakChecker, ObligationVar, VarState};
use asupersync::record::ObligationKind;
use asupersync::test_utils;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

// ============================================================================
// Test Data Generators
// ============================================================================

/// Generate arbitrary obligation variables.
fn arb_obligation_var() -> impl Strategy<Value = ObligationVar> {
    (0u32..10).prop_map(ObligationVar)
}

/// Generate arbitrary obligation kinds.
fn arb_obligation_kind() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
    ]
}

/// Generate arbitrary variable states.
fn arb_var_state() -> impl Strategy<Value = VarState> {
    prop_oneof![
        Just(VarState::Empty),
        Just(VarState::Resolved),
        arb_obligation_kind().prop_map(VarState::Held),
        arb_obligation_kind().prop_map(VarState::MayHold),
        Just(VarState::MayHoldAmbiguous),
    ]
}

/// Generate simple instructions (reserve, commit, abort).
fn arb_simple_instruction() -> impl Strategy<Value = Instruction> {
    prop_oneof![
        (arb_obligation_var(), arb_obligation_kind())
            .prop_map(|(var, kind)| Instruction::Reserve { var, kind }),
        arb_obligation_var().prop_map(|var| Instruction::Commit { var }),
        arb_obligation_var().prop_map(|var| Instruction::Abort { var }),
    ]
}

/// Generate instruction sequences without nested branches.
fn arb_instruction_sequence() -> impl Strategy<Value = Vec<Instruction>> {
    prop::collection::vec(arb_simple_instruction(), 0..8)
}

/// Generate branch instructions with simple arms.
fn arb_branch_instruction() -> impl Strategy<Value = Instruction> {
    prop::collection::vec(arb_instruction_sequence(), 1..4)
        .prop_map(|arms| Instruction::Branch { arms })
}

/// Generate full instruction sequences including branches.
fn arb_instructions() -> impl Strategy<Value = Vec<Instruction>> {
    prop::collection::vec(
        prop_oneof![arb_simple_instruction(), arb_branch_instruction(),],
        0..6,
    )
}

/// Generate obligation bodies.
fn arb_body() -> impl Strategy<Value = Body> {
    (any::<String>(), arb_instructions())
        .prop_map(|(name, instructions)| Body::new(name, instructions))
}

/// Generate variable mappings for renaming tests.
fn arb_var_mapping() -> impl Strategy<Value = BTreeMap<ObligationVar, ObligationVar>> {
    prop::collection::btree_map(arb_obligation_var(), arb_obligation_var(), 0..6)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Apply variable renaming to an instruction.
fn rename_instruction(
    instr: &Instruction,
    mapping: &BTreeMap<ObligationVar, ObligationVar>,
) -> Instruction {
    match instr {
        Instruction::Reserve { var, kind } => Instruction::Reserve {
            var: mapping.get(var).copied().unwrap_or(*var),
            kind: *kind,
        },
        Instruction::Commit { var } => Instruction::Commit {
            var: mapping.get(var).copied().unwrap_or(*var),
        },
        Instruction::Abort { var } => Instruction::Abort {
            var: mapping.get(var).copied().unwrap_or(*var),
        },
        Instruction::Branch { arms } => Instruction::Branch {
            arms: arms
                .iter()
                .map(|arm| rename_instructions(arm, mapping))
                .collect(),
        },
    }
}

/// Apply variable renaming to instruction sequence.
fn rename_instructions(
    instructions: &[Instruction],
    mapping: &BTreeMap<ObligationVar, ObligationVar>,
) -> Vec<Instruction> {
    instructions
        .iter()
        .map(|instr| rename_instruction(instr, mapping))
        .collect()
}

/// Apply variable renaming to a body.
fn rename_body(body: &Body, mapping: &BTreeMap<ObligationVar, ObligationVar>) -> Body {
    Body::new(
        body.name.clone(),
        rename_instructions(&body.instructions, mapping),
    )
}

/// Check if two diagnostic sets are equivalent (ignoring variable names).
fn diagnostics_equivalent(
    diag1: &[Diagnostic],
    diag2: &[Diagnostic],
    mapping: &BTreeMap<ObligationVar, ObligationVar>,
) -> bool {
    if diag1.len() != diag2.len() {
        return false;
    }

    // Simple check: for each diagnostic in diag1, find a corresponding one in diag2
    for d1 in diag1 {
        let mapped_var = mapping.get(&d1.var).copied().unwrap_or(d1.var);
        let found = diag2.iter().any(|d2| {
            d2.var == mapped_var
                && d2.obligation_kind == d1.obligation_kind
                && std::mem::discriminant(&d2.kind) == std::mem::discriminant(&d1.kind)
        });
        if !found {
            return false;
        }
    }

    true
}

/// Extract variables referenced in instructions.
fn extract_variables(instructions: &[Instruction]) -> BTreeSet<ObligationVar> {
    let mut vars = BTreeSet::new();
    for instr in instructions {
        match instr {
            Instruction::Reserve { var, .. } => {
                vars.insert(*var);
            }
            Instruction::Commit { var } | Instruction::Abort { var } => {
                vars.insert(*var);
            }
            Instruction::Branch { arms } => {
                for arm in arms {
                    vars.extend(extract_variables(arm));
                }
            }
        }
    }
    vars
}

/// Check if instructions are independent (don't share variables).
fn instructions_independent(instr1: &[Instruction], instr2: &[Instruction]) -> bool {
    let vars1 = extract_variables(instr1);
    let vars2 = extract_variables(instr2);
    vars1.is_disjoint(&vars2)
}

// ============================================================================
// Metamorphic Relations
// ============================================================================

/// MR1: Join Commutativity
/// For any two VarStates a, b: a.join(b) == b.join(a)
proptest! {
    #[test]
    fn mr1_join_commutativity(state1 in arb_var_state(), state2 in arb_var_state()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr1_join_commutativity");

        let result1 = state1.join(state2);
        let result2 = state2.join(state1);

        prop_assert_eq!(result1, result2,
            "Join operation must be commutative: {} ⊔ {} = {} ≠ {} = {} ⊔ {}",
            state1, state2, result1, result2, state2, state1);

        asupersync::test_complete!("mr1_join_commutativity");
    }
}

/// MR2: Join Associativity
/// For any VarStates a, b, c: (a.join(b)).join(c) == a.join(b.join(c))
proptest! {
    #[test]
    fn mr2_join_associativity(
        state1 in arb_var_state(),
        state2 in arb_var_state(),
        state3 in arb_var_state()
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr2_join_associativity");

        let left = state1.join(state2).join(state3);
        let right = state1.join(state2.join(state3));

        prop_assert_eq!(left, right,
            "Join operation must be associative: ({} ⊔ {}) ⊔ {} = {} ≠ {} = {} ⊔ ({} ⊔ {})",
            state1, state2, state3, left, right, state1, state2, state3);

        asupersync::test_complete!("mr2_join_associativity");
    }
}

/// MR3: Join Idempotence
/// For any VarState s: s.join(s) == s
proptest! {
    #[test]
    fn mr3_join_idempotence(state in arb_var_state()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr3_join_idempotence");

        let result = state.join(state);

        prop_assert_eq!(result, state,
            "Join operation must be idempotent: {} ⊔ {} = {} ≠ {}",
            state, state, result, state);

        asupersync::test_complete!("mr3_join_idempotence");
    }
}

/// MR4: Join Identity (Empty as Bottom)
/// For any VarState s: s.join(Empty) == s and Empty.join(s) == s
proptest! {
    #[test]
    fn mr4_join_identity(state in arb_var_state()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr4_join_identity");

        let result1 = state.join(VarState::Empty);
        let result2 = VarState::Empty.join(state);

        // Empty should be absorbed, except when joining with Resolved
        let expected = match state {
            VarState::Empty => VarState::Empty,
            VarState::Resolved => VarState::Resolved,
            _ => state,
        };

        prop_assert!(result1 == expected || (state == VarState::Resolved && result1 == VarState::Resolved),
            "Empty should act as identity for non-Resolved states: {} ⊔ Empty = {} (expected behavior varies)",
            state, result1);

        prop_assert!(result2 == expected || (state == VarState::Resolved && result2 == VarState::Resolved),
            "Empty should act as identity for non-Resolved states: Empty ⊔ {} = {} (expected behavior varies)",
            state, result2);

        asupersync::test_complete!("mr4_join_identity");
    }
}

/// MR5: Variable Renaming Equivalence
/// Consistently renaming variables should preserve leak detection results
proptest! {
    #[test]
    fn mr5_variable_renaming_equivalence(body in arb_body(), mapping in arb_var_mapping()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr5_variable_renaming_equivalence");

        // Skip if mapping is empty or creates conflicts
        if mapping.is_empty() {
            return Ok(());
        }

        let renamed_body = rename_body(&body, &mapping);

        let mut checker1 = LeakChecker::new();
        let mut checker2 = LeakChecker::new();

        let result1 = checker1.check(&body);
        let result2 = checker2.check(&renamed_body);

        // Results should be equivalent up to variable renaming
        prop_assert!(diagnostics_equivalent(&result1.diagnostics, &result2.diagnostics, &mapping),
            "Variable renaming should preserve diagnostic structure:\nOriginal: {} diagnostics\nRenamed: {} diagnostics",
            result1.diagnostics.len(), result2.diagnostics.len());

        prop_assert_eq!(result1.is_clean(), result2.is_clean(),
            "Variable renaming should preserve cleanliness: original={}, renamed={}",
            result1.is_clean(), result2.is_clean());

        asupersync::test_complete!("mr5_variable_renaming_equivalence");
    }
}

/// MR6: Instruction Reordering (Independent Operations)
/// Reordering independent instructions should not change the result
proptest! {
    #[test]
    fn mr6_instruction_reordering(
        seq1 in arb_instruction_sequence(),
        seq2 in arb_instruction_sequence(),
        scope_name in any::<String>()
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr6_instruction_reordering");

        // Only test if sequences are independent
        if !instructions_independent(&seq1, &seq2) {
            return Ok(());
        }

        let mut original = seq1.clone();
        original.extend(seq2.clone());
        let original_body = Body::new(scope_name.clone(), original);

        let mut reordered = seq2;
        reordered.extend(seq1);
        let reordered_body = Body::new(scope_name, reordered);

        let mut checker1 = LeakChecker::new();
        let mut checker2 = LeakChecker::new();

        let result1 = checker1.check(&original_body);
        let result2 = checker2.check(&reordered_body);

        prop_assert_eq!(result1.is_clean(), result2.is_clean(),
            "Reordering independent instructions should preserve cleanliness");

        prop_assert_eq!(result1.diagnostics.len(), result2.diagnostics.len(),
            "Reordering independent instructions should preserve diagnostic count");

        asupersync::test_complete!("mr6_instruction_reordering");
    }
}

/// MR7: Diagnostic Determinism
/// Running the checker multiple times on the same body should produce identical results
proptest! {
    #[test]
    fn mr7_diagnostic_determinism(body in arb_body()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr7_diagnostic_determinism");

        let mut checker1 = LeakChecker::new();
        let mut checker2 = LeakChecker::new();
        let mut checker3 = LeakChecker::new();

        let result1 = checker1.check(&body);
        let result2 = checker2.check(&body);
        let result3 = checker3.check(&body);

        prop_assert_eq!(result1.is_clean(), result2.is_clean(),
            "Multiple checker runs should have same cleanliness");
        prop_assert_eq!(result1.is_clean(), result3.is_clean(),
            "Multiple checker runs should have same cleanliness");

        prop_assert_eq!(result1.diagnostics.len(), result2.diagnostics.len(),
            "Multiple checker runs should have same diagnostic count");
        prop_assert_eq!(result1.diagnostics.len(), result3.diagnostics.len(),
            "Multiple checker runs should have same diagnostic count");

        asupersync::test_complete!("mr7_diagnostic_determinism");
    }
}

/// MR8: Budget Monotonicity
/// Adding more obligations should never decrease peak outstanding counts
proptest! {
    #[test]
    fn mr8_budget_monotonicity(
        base_instructions in arb_instruction_sequence(),
        additional_var in arb_obligation_var(),
        additional_kind in arb_obligation_kind(),
        scope_name in any::<String>()
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr8_budget_monotonicity");

        let base_vars = extract_variables(&base_instructions);

        // Only add if the variable is not already used
        if base_vars.contains(&additional_var) {
            return Ok(());
        }

        let base_body = Body::new(scope_name.clone(), base_instructions.clone());

        let mut extended_instructions = base_instructions;
        extended_instructions.push(Instruction::Reserve {
            var: additional_var,
            kind: additional_kind
        });
        let extended_body = Body::new(scope_name, extended_instructions);

        let mut checker1 = LeakChecker::new();
        let mut checker2 = LeakChecker::new();

        let base_result = checker1.check(&base_body);
        let extended_result = checker2.check(&extended_body);

        prop_assert!(
            extended_result.graded_budget.conservative_peak_outstanding
            >= base_result.graded_budget.conservative_peak_outstanding,
            "Adding obligations should not decrease peak outstanding: {} -> {}",
            base_result.graded_budget.conservative_peak_outstanding,
            extended_result.graded_budget.conservative_peak_outstanding
        );

        prop_assert!(
            extended_result.graded_budget.exit_outstanding_upper_bound
            >= base_result.graded_budget.exit_outstanding_upper_bound,
            "Adding obligations should not decrease exit bound: {} -> {}",
            base_result.graded_budget.exit_outstanding_upper_bound,
            extended_result.graded_budget.exit_outstanding_upper_bound
        );

        asupersync::test_complete!("mr8_budget_monotonicity");
    }
}

/// MR9: Branch Flattening Equivalence
/// Nested branches can be flattened to equivalent single-level branches
proptest! {
    #[test]
    fn mr9_branch_flattening_equivalence(
        var in arb_obligation_var(),
        kind in arb_obligation_kind(),
        scope_name in any::<String>()
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr9_branch_flattening_equivalence");

        // Create nested branch structure:
        // reserve(v)
        // branch { arm { branch { commit(v) | abort(v) } } | abort(v) }
        let nested_body = Body::new(scope_name.clone(), vec![
            Instruction::Reserve { var, kind },
            Instruction::Branch {
                arms: vec![
                    vec![Instruction::Branch {
                        arms: vec![
                            vec![Instruction::Commit { var }],
                            vec![Instruction::Abort { var }],
                        ]
                    }],
                    vec![Instruction::Abort { var }],
                ]
            }
        ]);

        // Create equivalent flattened structure:
        // reserve(v)
        // branch { commit(v) | abort(v) | abort(v) }
        let flat_body = Body::new(scope_name, vec![
            Instruction::Reserve { var, kind },
            Instruction::Branch {
                arms: vec![
                    vec![Instruction::Commit { var }],
                    vec![Instruction::Abort { var }],
                    vec![Instruction::Abort { var }],
                ]
            }
        ]);

        let mut checker1 = LeakChecker::new();
        let mut checker2 = LeakChecker::new();

        let nested_result = checker1.check(&nested_body);
        let flat_result = checker2.check(&flat_body);

        prop_assert_eq!(nested_result.is_clean(), flat_result.is_clean(),
            "Branch flattening should preserve cleanliness");

        prop_assert_eq!(nested_result.leaks().len(), flat_result.leaks().len(),
            "Branch flattening should preserve leak count");

        asupersync::test_complete!("mr9_branch_flattening_equivalence");
    }
}

/// MR10: Resolve Idempotence
/// Resolving an already resolved obligation should maintain resolved state
proptest! {
    #[test]
    fn mr10_resolve_idempotence(
        var in arb_obligation_var(),
        kind in arb_obligation_kind(),
        scope_name in any::<String>()
    ) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr10_resolve_idempotence");

        // Single resolution
        let single_resolve_body = Body::new(scope_name.clone(), vec![
            Instruction::Reserve { var, kind },
            Instruction::Commit { var },
        ]);

        // Double resolution (should error)
        let double_resolve_body = Body::new(scope_name, vec![
            Instruction::Reserve { var, kind },
            Instruction::Commit { var },
            Instruction::Commit { var }, // Should be detected as error
        ]);

        let mut checker1 = LeakChecker::new();
        let mut checker2 = LeakChecker::new();

        let single_result = checker1.check(&single_resolve_body);
        let double_result = checker2.check(&double_resolve_body);

        prop_assert!(single_result.is_clean(),
            "Single resolution should be clean");

        prop_assert!(!double_result.is_clean(),
            "Double resolution should be detected as error");

        let double_resolves = double_result.double_resolves();
        prop_assert_eq!(double_resolves.len(), 1,
            "Should detect exactly one double-resolve error");

        asupersync::test_complete!("mr10_resolve_idempotence");
    }
}

/// MR11: Empty Body Conservation
/// Empty bodies should always be clean and have zero budget
proptest! {
    #[test]
    fn mr11_empty_body_conservation(scope_name in any::<String>()) {
        test_utils::init_test_logging();
        asupersync::test_phase!("mr11_empty_body_conservation");

        let empty_body = Body::new(scope_name, vec![]);
        let mut checker = LeakChecker::new();
        let result = checker.check(&empty_body);

        prop_assert!(result.is_clean(),
            "Empty body should always be clean");

        prop_assert_eq!(result.diagnostics.len(), 0,
            "Empty body should have no diagnostics");

        prop_assert_eq!(result.graded_budget.conservative_peak_outstanding, 0,
            "Empty body should have zero peak outstanding obligations");

        prop_assert_eq!(result.graded_budget.exit_outstanding_upper_bound, 0,
            "Empty body should have zero exit outstanding obligations");

        asupersync::test_complete!("mr11_empty_body_conservation");
    }
}

/// MR12: Lattice Ordering Preservation
/// Join should preserve the partial order of the VarState lattice
#[test]
fn mr12_lattice_ordering_preservation() {
    test_utils::init_test_logging();
    asupersync::test_phase!("mr12_lattice_ordering_preservation");

    let kind = ObligationKind::SendPermit;

    // Test specific ordering relationships in the lattice
    let test_cases = vec![
        // Empty ⊑ everything except MayHoldAmbiguous when joined with different kinds
        (
            VarState::Empty,
            VarState::Held(kind),
            VarState::MayHold(kind),
        ),
        (
            VarState::Empty,
            VarState::MayHold(kind),
            VarState::MayHold(kind),
        ),
        (VarState::Empty, VarState::Resolved, VarState::Resolved),
        // Held(k) ⊔ Resolved = MayHold(k)
        (
            VarState::Held(kind),
            VarState::Resolved,
            VarState::MayHold(kind),
        ),
        // MayHold(k) ⊔ Resolved = MayHold(k)
        (
            VarState::MayHold(kind),
            VarState::Resolved,
            VarState::MayHold(kind),
        ),
        // Different kinds lead to ambiguous
        (
            VarState::Held(kind),
            VarState::Held(ObligationKind::IoOp),
            VarState::MayHoldAmbiguous,
        ),
        (
            VarState::MayHold(kind),
            VarState::MayHold(ObligationKind::IoOp),
            VarState::MayHoldAmbiguous,
        ),
    ];

    for (state1, state2, expected) in test_cases {
        let result1 = state1.join(state2);
        let result2 = state2.join(state1);

        assert_eq!(
            result1, expected,
            "Join {} ⊔ {} should equal {}, got {}",
            state1, state2, expected, result1
        );
        assert_eq!(
            result2, expected,
            "Join should be commutative: {} ⊔ {} should equal {}, got {}",
            state2, state1, expected, result2
        );
    }

    asupersync::test_complete!("mr12_lattice_ordering_preservation");
}

// ============================================================================
// Property-Based Test Configuration
// ============================================================================

#[cfg(test)]
mod proptest_config {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100,
            max_shrink_iters: 1000,
            timeout: 5000,
            .. ProptestConfig::default()
        })]
    }
}
